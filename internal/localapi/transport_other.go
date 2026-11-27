//go:build !linux && !windows

package localapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Other systems are not product targets; this keeps development builds
// working with a socket only its owner can open.

func DefaultAddr(dataDir string) string      { return filepath.Join(dataDir, "api.sock") }
func CandidateAddrs(dataDir string) []string { return []string{DefaultAddr(dataDir)} }

func Listen(addr string) (net.Listener, error) {
	os.MkdirAll(filepath.Dir(addr), 0o700)
	os.Remove(addr)
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return net.Listen("unix", addr)
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}
