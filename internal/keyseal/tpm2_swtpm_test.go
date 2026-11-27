package keyseal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// These tests run the real TPM 2.0 code against swtpm, a software TPM
// (apt install swtpm). They skip when swtpm is missing unless
// TRAFFICAM_REQUIRE_SWTPM=1, which CI sets so they can never silently skip.

type swtpm struct {
	addr string
	cmd  *exec.Cmd
}

func startSWTPM(t *testing.T, state string) *swtpm {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		if os.Getenv("TRAFFICAM_REQUIRE_SWTPM") == "1" {
			t.Fatal("swtpm required but not installed")
		}
		t.Skip("swtpm not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+state,
		"--server", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port+1),
		"--flags", "not-need-init,startup-clear")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &swtpm{addr: fmt.Sprintf("127.0.0.1:%d", port), cmd: cmd}
	t.Cleanup(s.stop)
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", s.addr); err == nil {
			c.Close()
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("swtpm did not start")
	return nil
}

func (s *swtpm) stop() {
	if s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}
}

// rawTCP is swtpm's data channel: plain TPM command bytes in, response out.
type rawTCP struct{ c net.Conn }

func (r *rawTCP) Send(cmd []byte) ([]byte, error) {
	if _, err := r.c.Write(cmd); err != nil {
		return nil, err
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(r.c, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[2:6])
	rest := make([]byte, n-10)
	if _, err := io.ReadFull(r.c, rest); err != nil {
		return nil, err
	}
	return append(hdr, rest...), nil
}
func (r *rawTCP) Close() error { return r.c.Close() }

func (s *swtpm) sealer() *TPM2 {
	return &TPM2{Name: "test-tpm2", Open: func() (transport.TPMCloser, error) {
		c, err := net.Dial("tcp", s.addr)
		if err != nil {
			return nil, err
		}
		return &rawTCP{c}, nil
	}}
}

func TestTPM2SealUnsealOnSoftwareTPM(t *testing.T) {
	s := startSWTPM(t, t.TempDir())
	tpm := s.sealer()
	if err := tpm.Available(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "db.key")
	p := &Sealed{Path: path, Sealers: []Sealer{tpm, &MachineID{ID: "m"}}, Logf: t.Logf}
	k1, err := p.Key()
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := p.Method(); m != "test-tpm2" {
		t.Fatalf("method %q", m)
	}
	k2, err := p.Key()
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("reopen: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, k1) {
		t.Fatal("key file contains the key in the clear")
	}

	// A flipped byte in the sealed private part is caught as tampering.
	bad := append([]byte(nil), raw...)
	bad[len(bad)-5] ^= 0xFF
	os.WriteFile(path, bad, 0o600)
	if _, err := p.Key(); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("tampered blob: want ErrSealMismatch, got %v", err)
	}
	os.WriteFile(path, raw, 0o600)

	// TPM switched off: unavailable, never "mismatch" (nothing gets destroyed).
	s.stop()
	if _, err := p.Key(); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSealMismatch) {
		t.Fatalf("TPM down: want ErrUnavailable only, got %v", err)
	}
}

func TestTPM2BlobFromAnotherTPMIsMismatch(t *testing.T) {
	a := startSWTPM(t, t.TempDir())
	b := startSWTPM(t, t.TempDir()) // a different chip: different seed
	blob, err := a.sealer().Seal(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.sealer().Unseal(blob); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("want ErrSealMismatch, got %v", err)
	}
}
