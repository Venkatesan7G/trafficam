//go:build linux

package keyseal

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestDefaultProviderOnLinux works with or without a TPM: without one (or
// without permission for /dev/tpmrm0) it must fall back to the machine id.
func TestDefaultProviderOnLinux(t *testing.T) {
	p := Default(filepath.Join(t.TempDir(), "db.key"))
	p.Logf = t.Logf
	k1, err := p.Key()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := p.Key()
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("reopen: %v", err)
	}
	m, _ := p.Method()
	t.Logf("sealed with %s", m)
}
