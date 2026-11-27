//go:build windows

package localapi

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// PipeName is the named pipe the service listens on.
const PipeName = `\\.\pipe\trafficam`

// pipeSDDL lets SYSTEM and Administrators do anything and the interactively
// logged-in user (IU) read and write. Network logons are not in IU, so the
// pipe is not reachable from another computer; remote pipe access is also
// refused below.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

func DefaultAddr(string) string      { return PipeName }
func CandidateAddrs(string) []string { return []string{PipeName} }

// Listen creates the named pipe. go-winio creates the first instance with
// FILE_FLAG_FIRST_PIPE_INSTANCE, so the call fails if another program has
// already taken the name, and rejects remote clients.
func Listen(addr string) (net.Listener, error) {
	return winio.ListenPipe(addr, &winio.PipeConfig{SecurityDescriptor: pipeSDDL, InputBufferSize: 64 << 10, OutputBufferSize: 64 << 10})
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}
