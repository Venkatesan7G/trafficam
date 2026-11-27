package keyseal

import (
	"bytes"
	"errors"
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
