//go:build linux

package linuxebpf

import "github.com/Venkatesan7G/trafficam/internal/event"

// setUnit records the systemd service unit (e.g. "nginx.service") on the
// program. Program.Key() includes it, so two services that run the same
// executable keep separate histories. Desktop apps have no unit ("").
func setUnit(p *event.Program, unit string) { p.Service = unit }
