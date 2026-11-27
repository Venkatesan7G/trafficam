// Package keyseal provides the database encryption key and protects it at rest.
//
// The key is random, 32 bytes, never typed by the user. It is stored "sealed":
// encrypted with a key that is only available on this machine, so copying the
// key file (or the whole data folder) to another PC gives an attacker nothing.
//
// Provider is an interface because the right sealing differs per OS:
//
//	Windows: DPAPI (CryptProtectData), optionally TPM-backed  -> windows thread
//	Linux:   TPM2 / kernel keyring where available            -> linux thread
//	Any:     MachineIDProvider below, a portable baseline
//
// HONEST LIMIT of MachineIDProvider: the machine id is readable by any local
// program running as the same user, so this defends against stolen files and
// copied backups, NOT against malware already running as you. The OS-specific
// providers should be stronger.
package keyseal

import (
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
// (copied from another machine, or tampered with).
var ErrSealMismatch = errors.New("keyseal: key file cannot be unsealed on this machine (copied or tampered)")

// Provider returns the database key, creating and sealing one on first use.
type Provider interface {
	Key() ([]byte, error)
}

// MachineIDProvider seals the key to a machine identifier.
type MachineIDProvider struct {
	Path      string // where the sealed key file lives
	MachineID string // override for tests; empty = read from the OS
}

func (p *MachineIDProvider) Key() ([]byte, error) {
	kek, err := p.kek()
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(p.Path)
	if errors.Is(err, os.ErrNotExist) {
		return p.create(kek)
	}
	if err != nil {
		return nil, err
	}
	return unseal(kek, blob)
}

func (p *MachineIDProvider) create(kek []byte) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	blob, err := seal(kek, key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p.Path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p.Path, blob, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// kek derives the key-encryption key from the machine id (HKDF-SHA256).
func (p *MachineIDProvider) kek() ([]byte, error) {
	id := p.MachineID
	if id == "" {
		var err error
		if id, err = readMachineID(); err != nil {
			return nil, err
		}
	}
	return hkdf.Key(sha256.New, []byte(id), []byte("trafficam-keyseal-v1"), "kek", keyLen)
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

// readMachineID is the portable best effort; OS providers replace it.
func readMachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("keyseal: no machine id available; an OS-specific Provider is needed on this platform")
}
