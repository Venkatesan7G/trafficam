//go:build linux

package linuxebpf

import "github.com/Venkatesan7G/trafficam/internal/event"

// setUnit records the systemd unit on the program.
//
// TODO(after the Windows collector PR merges): that PR adds
// event.Program.Service (and makes Program.Key() include it, so services
// sharing one executable get separate histories). Replace the body with
//
//	p.Service = unit
//
// Until then the unit is resolved and tested, but not passed on.
func setUnit(p *event.Program, unit string) {
	_ = p
	_ = unit
}
