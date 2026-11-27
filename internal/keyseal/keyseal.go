// Package keyseal provides the database encryption key and protects it at rest.
//
// The key is random, 32 bytes, never typed by the user. It is stored "sealed":
// encrypted by something that only exists on this machine, so copying the key
// file (or the whole data folder) somewhere else gives an attacker nothing.
//
// What does the sealing depends on the OS. Default() tries the strongest
// option first and falls back, never failing just because a TPM is missing:
//
//	Windows: "windows-tpm"  TPM key (Microsoft Platform Crypto Provider), then DPAPI on top
//	         "dpapi"        DPAPI only (CryptProtectData, tied to the Windows account)
//	Linux:   "linux-tpm2"   TPM 2.0 sealed object via /dev/tpmrm0
//	         "machine-id"   key derived from /etc/machine-id (weakest, see below)
//
// The key file starts with a small header naming the method, so a file made
// by one method is always opened by the same method. Old files from before
// the header existed are machine-id files; they are upgraded to the best
// method available the first time they are opened.
//
// HONEST LIMITS (also in docs/KEYS.md):
//   - Nothing here protects the key from malware already running as
//     administrator/root on this PC while it is switched on: such a program
//     can ask the TPM or DPAPI to unseal, exactly like trafficam does.
//   - "machine-id" only stops someone who copies the data folder alone. The
//     machine id sits on the same disk, so a stolen disk can be unsealed.
//   - TPM methods stop a stolen disk or copied files, because the TPM chip
//     stays behind. Clearing the TPM (BIOS reset, some firmware updates)
//     makes the key unrecoverable: the history is lost and learning restarts.
//   - The Linux kernel keyring is not used: it forgets everything at reboot,
//     so it cannot keep a key "at rest".
package keyseal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keyLen = 32

// ErrSealMismatch means the key file exists but cannot be unsealed here
// (copied from another machine, or tampered with). The tamper response treats
// this as tampering.
var ErrSealMismatch = errors.New("keyseal: key file cannot be unsealed on this machine (copied or tampered)")

// ErrUnavailable means the method that sealed the key file cannot be used
// right now (no TPM device, no permission, service not running). It is NOT
// evidence of tampering: the key file may be fine, so it must not be deleted.
var ErrUnavailable = errors.New("keyseal: the method that sealed this key is not available right now")

// Provider returns the database key, creating and sealing one on first use.
type Provider interface {
	Key() ([]byte, error)
}

// Sealer is one way of protecting the key at rest.
type Sealer interface {
	// Method is the short name written into the key file header.
	Method() string
	// Available reports whether the method works here (nil = yes).
	Available() error
	// Seal protects key; Unseal reverses it. Unseal returns an error wrapping
	// ErrSealMismatch when the blob is not valid for this machine, and one
	// wrapping ErrUnavailable when the method cannot run at all.
	Seal(key []byte) ([]byte, error)
	Unseal(blob []byte) ([]byte, error)
}

// magic starts every key file written by this version.
var magic = []byte("TCK2")

// Sealed is the normal Provider: it stores the key at Path, sealed with the
// first working Sealer in Sealers (best first).
type Sealed struct {
	Path    string
	Sealers []Sealer
	// Legacy opens headerless key files from before the header existed. It
	// is the machine-id sealer; nil means such files are rejected.
	Legacy Sealer
	// Logf, if set, is told which method is used and about upgrades.
	Logf func(format string, args ...any)
}

// Default returns the provider for this OS, storing the key at path.
func Default(path string) *Sealed {
	return &Sealed{Path: path, Sealers: platformSealers(), Legacy: &MachineID{}}
}

func (p *Sealed) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

// Method reports which method protects the existing key file ("" if none).
func (p *Sealed) Method() (string, error) {
	blob, err := os.ReadFile(p.Path)
	if err != nil {
		return "", err
	}
	m, _, ok := parse(blob)
	if !ok {
		return "machine-id (old format)", nil
	}
	return m, nil
}

func (p *Sealed) Key() ([]byte, error) {
	blob, err := os.ReadFile(p.Path)
	if errors.Is(err, os.ErrNotExist) {
		return p.create()
	}
	if err != nil {
		return nil, err
	}
	method, inner, ok := parse(blob)
	if !ok { // headerless: written before methods existed
		if p.Legacy == nil {
			return nil, fmt.Errorf("%w: unknown key file format", ErrSealMismatch)
		}
		key, err := p.Legacy.Unseal(blob)
		if err != nil {
			return nil, err
		}
		p.upgrade(key, "old machine-id file")
		return key, nil
	}
	s := p.find(method)
	if s == nil {
		return nil, fmt.Errorf("%w: key was sealed with %q, which this build does not support", ErrUnavailable, method)
	}
	key, err := s.Unseal(inner)
	if err != nil {
		return nil, err
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("%w: unsealed key has the wrong length", ErrSealMismatch)
	}
	// A stronger method may have become available (TPM enabled later).
	if best := p.best(); best != nil && rank(p.Sealers, best.Method()) < rank(p.Sealers, method) {
		p.upgrade(key, method)
	}
	return key, nil
}

func (p *Sealed) find(method string) Sealer {
	for _, s := range p.Sealers {
		if s.Method() == method {
			return s
		}
	}
	if p.Legacy != nil && p.Legacy.Method() == method {
		return p.Legacy
	}
	return nil
}

func rank(ss []Sealer, method string) int {
	for i, s := range ss {
		if s.Method() == method {
			return i
		}
	}
	return len(ss)
}

// best returns the first sealer that is available here.
func (p *Sealed) best() Sealer {
	for _, s := range p.Sealers {
		if err := s.Available(); err == nil {
			return s
		} else {
			p.logf("keyseal: %s not available: %v", s.Method(), err)
		}
	}
	return nil
}

// sealWithBest seals key with the first sealer that works AND round-trips:
// a sealer is only trusted after it has unsealed its own output once, so a
// half-working TPM never leaves us with a key we cannot open tomorrow.
func (p *Sealed) sealWithBest(key []byte) ([]byte, string, error) {
	var errs []error
	for _, s := range p.Sealers {
		if err := s.Available(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Method(), err))
			continue
		}
		inner, err := s.Seal(key)
		if err == nil {
			var back []byte
			if back, err = s.Unseal(inner); err == nil && !bytes.Equal(back, key) {
				err = errors.New("round trip returned a different key")
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Method(), err))
			continue
		}
		if len(errs) > 0 {
			p.logf("keyseal: skipped: %v", errors.Join(errs...))
		}
		return frame(s.Method(), inner), s.Method(), nil
	}
	return nil, "", fmt.Errorf("keyseal: no way to seal the key on this machine: %w", errors.Join(errs...))
}

func (p *Sealed) create() ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	blob, method, err := p.sealWithBest(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p.Path), 0o700); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(p.Path, blob, 0o600); err != nil {
		return nil, err
	}
	p.logf("keyseal: new database key sealed with %s", method)
	return key, nil
}

// upgrade re-seals an existing key with the best method. Failure is logged
// and harmless: the old file still works.
func (p *Sealed) upgrade(key []byte, from string) {
	blob, method, err := p.sealWithBest(key)
	if err != nil {
		p.logf("keyseal: could not upgrade key from %s: %v", from, err)
		return
	}
	if err := WriteFileAtomic(p.Path, blob, 0o600); err != nil {
		p.logf("keyseal: could not write upgraded key: %v", err)
		return
	}
	p.logf("keyseal: key upgraded from %s to %s", from, method)
}

// frame = magic | len(method) u8 | method | inner
func frame(method string, inner []byte) []byte {
	out := make([]byte, 0, len(magic)+1+len(method)+len(inner))
	out = append(out, magic...)
	out = append(out, byte(len(method)))
	out = append(out, method...)
	return append(out, inner...)
}

func parse(blob []byte) (method string, inner []byte, ok bool) {
	if !bytes.HasPrefix(blob, magic) || len(blob) < len(magic)+1 {
		return "", nil, false
	}
	n := int(blob[len(magic)])
	rest := blob[len(magic)+1:]
	if n == 0 || len(rest) < n {
		return "", nil, false
	}
	return string(rest[:n]), rest[n:], true
}

// WriteFileAtomic writes data to a temporary file next to path, flushes it to
// disk and renames it into place, so a crash or power cut never leaves a
// half-written key file (which would look exactly like tampering).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(perm); err != nil && !isWindows {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// MachineID seals the key to a machine identifier (AES-256-GCM under a key
// derived with HKDF-SHA256). It is the portable fallback; see the package
// comment for why it is the weakest method.
type MachineID struct {
	ID string // override for tests; empty = read from the OS
}

func (m *MachineID) Method() string { return "machine-id" }

func (m *MachineID) Available() error { _, err := m.kek(); return err }

func (m *MachineID) Seal(key []byte) ([]byte, error) {
	kek, err := m.kek()
	if err != nil {
		return nil, err
	}
	return seal(kek, key)
}

func (m *MachineID) Unseal(blob []byte) ([]byte, error) {
	kek, err := m.kek()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return unseal(kek, blob)
}

func (m *MachineID) kek() ([]byte, error) {
	id := m.ID
	if id == "" {
		var err error
		if id, err = readMachineID(); err != nil {
			return nil, err
		}
	}
	return hkdf.Key(sha256.New, []byte(id), []byte("trafficam-keyseal-v1"), "kek", keyLen)
}

// MachineIDProvider is the original provider, kept for callers and tests:
// a key file sealed only with the machine id, in the old headerless format.
type MachineIDProvider struct {
	Path      string // where the sealed key file lives
	MachineID string // override for tests; empty = read from the OS
}

func (p *MachineIDProvider) Key() ([]byte, error) {
	m := &MachineID{ID: p.MachineID}
	blob, err := os.ReadFile(p.Path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, keyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		blob, err := m.Seal(key)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(p.Path), 0o700); err != nil {
			return nil, err
		}
		return key, WriteFileAtomic(p.Path, blob, 0o600)
	}
	if err != nil {
		return nil, err
	}
	return m.Unseal(blob)
}

func seal(kek, key []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, key, nil), nil // nonce || ciphertext
}

func unseal(kek, blob []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, ErrSealMismatch
	}
	key, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		return nil, ErrSealMismatch
	}
	return key, nil
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// readMachineID is the portable best effort.
func readMachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("keyseal: no machine id available on this platform")
}
