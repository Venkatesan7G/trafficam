package keyseal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyStableAndMachineBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.key")
	a := &MachineIDProvider{Path: path, MachineID: "machine-A"}
	k1, err := a.Key()
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %v len=%d", err, len(k1))
	}
	k2, _ := a.Key()
	if !bytes.Equal(k1, k2) {
		t.Fatal("key changed between calls")
	}
	// Same file on a "different machine" must not unseal.
	b := &MachineIDProvider{Path: path, MachineID: "machine-B"}
	if _, err := b.Key(); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("want ErrSealMismatch, got %v", err)
	}
}

// fake is a test sealer: XOR with a per-"machine" byte, with a check byte.
type fake struct {
	name    string
	machine byte
	down    error // Available() result
	seals   int
}

func (f *fake) Method() string   { return f.name }
func (f *fake) Available() error { return f.down }
func (f *fake) Seal(k []byte) ([]byte, error) {
	if f.down != nil {
		return nil, f.down
	}
	f.seals++
	out := []byte{f.machine}
	for _, b := range k {
		out = append(out, b^f.machine)
	}
	return out, nil
}
func (f *fake) Unseal(b []byte) ([]byte, error) {
	if f.down != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, f.down)
	}
	if len(b) == 0 || b[0] != f.machine {
		return nil, ErrSealMismatch
	}
	out := make([]byte, 0, len(b)-1)
	for _, x := range b[1:] {
		out = append(out, x^f.machine)
	}
	return out, nil
}

func TestBestAvailableMethodIsUsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.key")
	tpm := &fake{name: "tpm", machine: 7, down: errors.New("no chip")}
	soft := &fake{name: "soft", machine: 7}
	p := &Sealed{Path: path, Sealers: []Sealer{tpm, soft}}
	k1, err := p.Key()
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := p.Method(); m != "soft" {
		t.Fatalf("method %q, want soft (tpm is down)", m)
	}
	// The TPM appears later: the key stays the same and is upgraded.
	tpm.down = nil
	k2, err := p.Key()
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("key changed or failed: %v", err)
	}
	if m, _ := p.Method(); m != "tpm" {
		t.Fatalf("method %q after upgrade, want tpm", m)
	}
	// Opening again does not re-seal.
	seals := tpm.seals
	if _, err := p.Key(); err != nil || tpm.seals != seals {
		t.Fatalf("unexpected reseal (%d -> %d) or error %v", seals, tpm.seals, err)
	}
}

func TestOtherMachineIsMismatchAndDownIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.key")
	a := &Sealed{Path: path, Sealers: []Sealer{&fake{name: "tpm", machine: 1}}}
	if _, err := a.Key(); err != nil {
		t.Fatal(err)
	}
	other := &Sealed{Path: path, Sealers: []Sealer{&fake{name: "tpm", machine: 2}}}
	if _, err := other.Key(); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("other machine: want ErrSealMismatch, got %v", err)
	}
	down := &Sealed{Path: path, Sealers: []Sealer{&fake{name: "tpm", machine: 1, down: errors.New("busy")}}}
	if _, err := down.Key(); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSealMismatch) {
		t.Fatalf("TPM down: want only ErrUnavailable, got %v", err)
	}
	unknown := &Sealed{Path: path, Sealers: []Sealer{&fake{name: "dpapi", machine: 1}}}
	if _, err := unknown.Key(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown method: want ErrUnavailable, got %v", err)
	}
}

func TestLegacyFileIsUpgradedAndKeyKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.key")
	old, err := (&MachineIDProvider{Path: path, MachineID: "m"}).Key()
	if err != nil {
		t.Fatal(err)
	}
	p := &Sealed{Path: path, Sealers: []Sealer{&fake{name: "tpm", machine: 3}}, Legacy: &MachineID{ID: "m"}}
	k, err := p.Key()
	if err != nil || !bytes.Equal(k, old) {
		t.Fatalf("legacy key not kept: %v", err)
	}
	if m, _ := p.Method(); m != "tpm" {
		t.Fatalf("legacy file not upgraded: %q", m)
	}
	if k2, err := p.Key(); err != nil || !bytes.Equal(k2, old) {
		t.Fatalf("after upgrade: %v", err)
	}
}

func TestBrokenSealerIsSkipped(t *testing.T) {
	// A sealer whose output it cannot read back must never be trusted.
	path := filepath.Join(t.TempDir(), "db.key")
	p := &Sealed{Path: path, Sealers: []Sealer{&liar{}, &fake{name: "soft", machine: 9}}}
	if _, err := p.Key(); err != nil {
		t.Fatal(err)
	}
	if m, _ := p.Method(); m != "soft" {
		t.Fatalf("broken sealer was used: %q", m)
	}
}

type liar struct{}

func (liar) Method() string                  { return "liar" }
func (liar) Available() error                { return nil }
func (liar) Seal(k []byte) ([]byte, error)   { return []byte("x"), nil }
func (liar) Unseal(b []byte) ([]byte, error) { return make([]byte, 32), nil }

func TestTruncatedFileIsMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.key")
	p := &Sealed{Path: path, Sealers: []Sealer{&MachineID{ID: "m"}}}
	if _, err := p.Key(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, b[:len(b)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Key(); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("want ErrSealMismatch, got %v", err)
	}
}

func TestAtomicWriteLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	for i := 0; i < 3; i++ {
		if err := WriteFileAtomic(path, []byte{byte(i)}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}
