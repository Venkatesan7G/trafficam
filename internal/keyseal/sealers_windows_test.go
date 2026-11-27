//go:build windows

package keyseal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	blob, err := DPAPI{}.Seal(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DPAPI{}.Unseal(blob)
	if err != nil || !bytes.Equal(back, key) {
		t.Fatalf("round trip: %v", err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := (DPAPI{}).Unseal(blob); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("tampered: want ErrSealMismatch, got %v", err)
	}
}

func TestDefaultProviderOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.key")
	p := Default(path)
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
	if m != "dpapi" && m != "windows-tpm" {
		t.Fatalf("unexpected method %q", m)
	}
	if m == "windows-tpm" {
		// The default key name is shared with real installs: leave it.
		return
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, k1) {
		t.Fatal("key in the clear")
	}
}

// TestWindowsTPM runs only where a TPM is present (most real PCs; GitHub's
// runners usually have none, so it logs and skips there).
func TestWindowsTPM(t *testing.T) {
	w := &WindowsTPM{KeyName: "trafficam-test-key-seal"}
	if err := w.Available(); err != nil {
		if os.Getenv("TRAFFICAM_REQUIRE_WINTPM") == "1" {
			t.Fatal(err)
		}
		t.Skipf("no TPM here: %v", err)
	}
	t.Cleanup(func() { _ = w.DeleteKey() })
	key := bytes.Repeat([]byte{7}, 32)
	blob, err := w.Seal(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := w.Unseal(blob)
	if err != nil || !bytes.Equal(back, key) {
		t.Fatalf("round trip: %v", err)
	}
	if err := w.DeleteKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unseal(blob); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("after deleting the TPM key: want ErrSealMismatch, got %v", err)
	}
}
