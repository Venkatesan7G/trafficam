//go:build linux

package localapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOtherUserIsRefused runs a client as the "nobody" user and checks the
// socket turns it away. It needs root (to switch user), so it is skipped in
// normal runs; CI's Linux jobs run as a sudo-capable user.
func TestOtherUserIsRefused(t *testing.T) {
	if os.Getenv("TRAFFICAM_HELPER_DIAL") != "" {
		c := NewClient(os.Getenv("TRAFFICAM_HELPER_DIAL"))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := c.Status(ctx); err == nil {
			os.Exit(0) // allowed: the test will fail
		}
		os.Exit(3) // refused, as it should be
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a client as another user")
	}
	// A world-readable folder, so that only the socket check (not folder
	// permissions) can turn the other user away.
	dir, err := os.MkdirTemp("", "trafficam-auth-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o755)
	_, _, addr := startServerIn(t, dir)
	os.Chmod(addr, 0o666)
	// Copy this test binary somewhere nobody can run it from.
	self, _ := os.Executable()
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "helper.test")
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run", "^TestOtherUserIsRefused$")
	cmd.Env = append(os.Environ(), "TRAFFICAM_HELPER_DIAL="+addr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := cmd.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 3 {
		t.Fatalf("other user was not refused (err=%v): %s", err, out)
	}
}
