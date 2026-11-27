// Package pack installs and loads signed offline "knowledge packs": the
// files trafficam can be updated with, without any server.
//
// A pack is one .tar file that you download (or copy from a USB stick) and
// install by hand with "trafficam pack install FILE". trafficam itself never
// connects anywhere to fetch one. Inside:
//
//	manifest.json          what is in the pack: sequence number and SHA-256 of every file
//	manifest.json.minisig  minisign (Ed25519) signature of manifest.json
//	files/<name>           the data files
//
// Known files (each optional):
//
//	blocklist.txt       known-bad destinations, blocklist format      kind "blocklist"
//	prior.tcw           head C weights, TCW1 KindPrior                kind "prior"
//	prior.sources.json  datasets and licences behind prior.tcw        kind "prior-sources"
//	trusted-os.json     core OS programs whose novelty is not alerted kind "trusted-os"
//	asn.csv.gz          offline IP -> network owner/country table     kind "asn"
//	SOURCES.md          where every file came from                    kind "sources"
//
// Security model: only manifest.json is signed; it pins every file by
// SHA-256, so changing any byte of any file breaks verification. The public
// keys allowed to sign are compiled into trafficam (keys.go). Installing a
// pack with a lower sequence number than the installed one is refused, so an
// old pack with an old blocklist cannot be replayed. The installed pack is
// verified again at every start, so editing files on disk is noticed too.
package pack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// Format is the manifest format this build understands.
const Format = 1

const (
	ManifestName  = "manifest.json"
	SignatureName = "manifest.json.minisig"
	filesPrefix   = "files/"

	maxManifest = 1 << 20
	maxFile     = 256 << 20
)

// Kinds trafficam knows how to use. Files of other kinds are verified and
// kept but not used (a newer pack on an older trafficam).
const (
	KindBlocklist    = "blocklist"
	KindPrior        = "prior"
	KindPriorSources = "prior-sources"
	KindTrustedOS    = "trusted-os"
	KindASN          = "asn"
	KindSources      = "sources"
)

// Manifest is manifest.json.
type Manifest struct {
	Format      int    `json:"format"`
	Seq         uint64 `json:"seq"`     // strictly increasing between releases
	Created     string `json:"created"` // YYYY-MM-DD, informational only
	Description string `json:"description,omitempty"`
	Files       []File `json:"files"`
}

// File is one entry of the manifest.
type File struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func (m *Manifest) validate() error {
	if m.Format != Format {
		return fmt.Errorf("pack: manifest format %d, this trafficam understands %d (update trafficam)", m.Format, Format)
	}
	if m.Seq == 0 {
		return errors.New("pack: manifest has no sequence number")
	}
	seen := map[string]bool{}
	kinds := map[string]bool{}
	for _, f := range m.Files {
		if !nameRE.MatchString(f.Name) || f.Name == ManifestName || f.Name == SignatureName {
			return fmt.Errorf("pack: bad file name %q", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("pack: file %q listed twice", f.Name)
		}
		seen[f.Name] = true
		if f.Kind != "" && kinds[f.Kind] {
			return fmt.Errorf("pack: two files of kind %q", f.Kind)
		}
		kinds[f.Kind] = true
		if f.Size < 0 || f.Size > maxFile {
			return fmt.Errorf("pack: file %q has bad size %d", f.Name, f.Size)
		}
		if b, err := hex.DecodeString(f.SHA256); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("pack: file %q has a bad sha256", f.Name)
		}
	}
	return nil
}

// Installed is a verified pack on disk.
type Installed struct {
	Dir      string // folder with the files
	Manifest Manifest
	SignedBy string // key id
}

// Path returns the file of a kind, or "" if the pack has none.
func (p *Installed) Path(kind string) string {
	if p == nil {
		return ""
	}
	for _, f := range p.Manifest.Files {
		if f.Kind == kind {
			return filepath.Join(p.Dir, f.Name)
		}
	}
	return ""
}

// Dir layout inside the data folder.
func currentDir(data string) string  { return filepath.Join(data, "packs", "current") }
func previousDir(data string) string { return filepath.Join(data, "packs", "previous") }

// verifyManifest checks the signature and parses the manifest.
func verifyManifest(keys []PublicKey, manifest, sig []byte) (Manifest, PublicKey, error) {
	if len(keys) == 0 {
		return Manifest{}, PublicKey{}, ErrNoKeys
	}
	s, err := ParseSignature(sig)
	if err != nil {
		return Manifest{}, PublicKey{}, err
	}
	k, err := Verify(keys, manifest, s)
	if err != nil {
		return Manifest{}, PublicKey{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, PublicKey{}, fmt.Errorf("pack: manifest: %w", err)
	}
	return m, k, m.validate()
}

// Load verifies and returns the installed pack, or (nil, nil) if none is
// installed. Any mismatch is an error: a pack that fails verification is
// never used, not even partly.
func Load(data string, keys []PublicKey) (*Installed, error) {
	dir := currentDir(data)
	manifest, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, SignatureName))
	if err != nil {
		return nil, fmt.Errorf("pack: installed pack has no signature: %w", err)
	}
	m, k, err := verifyManifest(keys, manifest, sig)
	if err != nil {
		return nil, fmt.Errorf("installed pack in %s: %w", dir, err)
	}
	for _, f := range m.Files {
		if err := checkFile(filepath.Join(dir, f.Name), f); err != nil {
			return nil, fmt.Errorf("installed pack in %s: %w", dir, err)
		}
	}
	return &Installed{Dir: dir, Manifest: m, SignedBy: k.KeyID()}, nil
}

func checkFile(path string, f File) error {
	fh, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("pack: %s: %w", f.Name, err)
	}
	defer fh.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(fh, maxFile+1))
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("pack: %s does not match its signed checksum (modified?)", f.Name)
	}
	return nil
}

// ErrOlder means the pack is not newer than the installed one.
var ErrOlder = errors.New("pack: this pack is not newer than the installed one")

// ErrNoKeys means this build has no trusted signing key, so no pack can be
// installed. See docs/PACKS.md for how the release key is set.
var ErrNoKeys = errors.New("pack: this build of trafficam has no trusted pack signing key (see docs/PACKS.md)")

// Verify checks a pack file completely without installing it.
func VerifyFile(path string, keys []PublicKey) (*Manifest, string, error) {
	var m *Manifest
	var who string
	err := readPack(path, keys, func(man Manifest, k PublicKey) error {
		m, who = &man, k.KeyID()
		return nil
	}, func(File, io.Reader) error { return nil })
	return m, who, err
}

// Install verifies a pack file and makes it the current pack. Nothing is
// changed unless every check passes. The pack it replaces is kept as
// packs/previous.
func Install(path, data string, keys []PublicKey) (*Installed, error) {
	var installedSeq uint64
	if cur, err := Load(data, keys); err == nil && cur != nil {
		installedSeq = cur.Manifest.Seq
	}
	// A current pack that fails verification does not block a newer one.

	if err := os.MkdirAll(filepath.Join(data, "packs"), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(filepath.Join(data, "packs"), ".incoming-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp) // no-op after the rename

	var man Manifest
	var who PublicKey
	var rawManifest, rawSig []byte
	err = readPackRaw(path, keys, func(m Manifest, k PublicKey, mb, sb []byte) error {
		if m.Seq <= installedSeq {
			return fmt.Errorf("%w (pack %d, installed %d)", ErrOlder, m.Seq, installedSeq)
		}
		man, who, rawManifest, rawSig = m, k, mb, sb
		return nil
	}, func(f File, r io.Reader) error {
		out, err := os.OpenFile(filepath.Join(tmp, f.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, r); err != nil {
			out.Close()
			return err
		}
		if err := out.Sync(); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		return nil, err
	}
	for name, b := range map[string][]byte{ManifestName: rawManifest, SignatureName: rawSig} {
		if err := os.WriteFile(filepath.Join(tmp, name), b, 0o644); err != nil {
			return nil, err
		}
	}
	// Swap: current -> previous, incoming -> current.
	cur, prev := currentDir(data), previousDir(data)
	if err := os.RemoveAll(prev); err != nil {
		return nil, err
	}
	if _, err := os.Stat(cur); err == nil {
		if err := os.Rename(cur, prev); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, cur); err != nil {
		return nil, err
	}
	return &Installed{Dir: cur, Manifest: man, SignedBy: who.KeyID()}, nil
}

func readPack(path string, keys []PublicKey, onManifest func(Manifest, PublicKey) error, onFile func(File, io.Reader) error) error {
	return readPackRaw(path, keys, func(m Manifest, k PublicKey, _, _ []byte) error { return onManifest(m, k) }, onFile)
}

// readPackRaw streams a pack: the manifest and signature must be the first
// two entries, so the signature is checked before any file is read, and every
// file is hashed while it is passed to onFile. onFile's writes are only kept
// by the caller if the whole call returns nil.
func readPackRaw(path string, keys []PublicKey,
	onManifest func(Manifest, PublicKey, []byte, []byte) error,
	onFile func(File, io.Reader) error) error {

	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	tr := tar.NewReader(fh)

	next := func(want string, limit int64) ([]byte, error) {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("pack: %s missing: %w", want, err)
		}
		if h.Name != want || h.Typeflag != tar.TypeReg || h.Size > limit {
			return nil, fmt.Errorf("pack: expected %s first, found %q", want, h.Name)
		}
		return io.ReadAll(tr)
	}
	rawManifest, err := next(ManifestName, maxManifest)
	if err != nil {
		return err
	}
	rawSig, err := next(SignatureName, 64<<10)
	if err != nil {
		return err
	}
	m, k, err := verifyManifest(keys, rawManifest, rawSig)
	if err != nil {
		return err
	}
	if err := onManifest(m, k, rawManifest, rawSig); err != nil {
		return err
	}
	want := map[string]File{}
	for _, f := range m.Files {
		want[filesPrefix+f.Name] = f
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("pack: %w", err)
		}
		f, ok := want[h.Name]
		if !ok || h.Typeflag != tar.TypeReg {
			return fmt.Errorf("pack: unexpected entry %q (not in the signed manifest)", h.Name)
		}
		delete(want, h.Name)
		if h.Size != f.Size {
			return fmt.Errorf("pack: %s has size %d, manifest says %d", f.Name, h.Size, f.Size)
		}
		sum := sha256.New()
		body := io.TeeReader(io.LimitReader(tr, f.Size), sum)
		if err := onFile(f, body); err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, body); err != nil { // hash what onFile did not read
			return err
		}
		if hex.EncodeToString(sum.Sum(nil)) != f.SHA256 {
			return fmt.Errorf("pack: %s does not match its signed checksum (modified?)", f.Name)
		}
	}
	if len(want) > 0 {
		var missing []string
		for n := range want {
			missing = append(missing, n)
		}
		sort.Strings(missing)
		return fmt.Errorf("pack: files missing from the archive: %v", missing)
	}
	return nil
}
