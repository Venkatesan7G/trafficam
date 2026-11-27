//go:build linux

package localapi

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// GroupName is the Unix group whose members may use the local API (the
// installer adds the desktop user to it). root always may.
const GroupName = "trafficam"

// SystemSocket is where the service listens when it runs as root.
const SystemSocket = "/run/trafficam/api.sock"

// DefaultAddr is where a service running with this user's rights listens.
func DefaultAddr(dataDir string) string {
	if os.Geteuid() == 0 {
		return SystemSocket
	}
	return filepath.Join(dataDir, "api.sock")
}

// CandidateAddrs are the places a desktop agent should try, in order.
func CandidateAddrs(dataDir string) []string {
	return []string{SystemSocket, filepath.Join(dataDir, "api.sock")}
}

// Listen opens the Unix socket and returns a listener that only hands out
// connections from allowed users (checked with SO_PEERCRED, which the kernel
// fills in and the caller cannot fake).
func Listen(addr string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(addr), 0o755); err != nil {
		return nil, err
	}
	if c, err := net.Dial("unix", addr); err == nil {
		c.Close()
		return nil, fmt.Errorf("another trafficam is already answering on %s", addr)
	}
	os.Remove(addr) // stale socket from a crash
	// Create the socket with no access at all, then open it up: no window
	// where anyone else could connect.
	old := unix.Umask(0o177)
	l, err := net.Listen("unix", addr)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	gid := -1
	if g, err := user.LookupGroup(GroupName); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if gid >= 0 && os.Geteuid() == 0 {
		if err := os.Chown(addr, 0, gid); err == nil {
			os.Chmod(addr, 0o660)
		}
	}
	return &authListener{Listener: l, gid: gid, self: os.Geteuid()}, nil
}

type authListener struct {
	net.Listener
	gid  int // -1 = no trafficam group on this machine
	self int
}

// Accept returns the next allowed connection; others are closed at once.
func (a *authListener) Accept() (net.Conn, error) {
	for {
		c, err := a.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if a.allowed(c) {
			return c, nil
		}
		c.Close()
	}
}

func (a *authListener) allowed(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var cerr error
	raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if cerr != nil || cred == nil {
		return false
	}
	if cred.Uid == 0 || int(cred.Uid) == a.self {
		return true
	}
	if a.gid < 0 {
		return false
	}
	if int(cred.Gid) == a.gid {
		return true
	}
	return inGroup(int(cred.Pid), a.gid)
}

// inGroup reads the caller's supplementary groups from /proc.
func inGroup(pid, gid int) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Groups:"); ok {
			for _, g := range strings.Fields(rest) {
				if n, err := strconv.Atoi(g); err == nil && n == gid {
					return true
				}
			}
			return false
		}
	}
	return false
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}
