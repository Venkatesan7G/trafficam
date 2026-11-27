package collector

import (
	"context"
	"net/netip"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Synthetic is a mock collector that generates plausible traffic. It is used
// for demos and tests when no real capture is available (e.g. on a laptop
// without root, or in CI). Output is deterministic for a given Start time.
type Synthetic struct {
	Start time.Time     // timestamp of the first flow
	Step  time.Duration // time between flows (event time)
	Count int           // number of flows to emit
	Sleep time.Duration // real delay between flows; 0 = as fast as possible
	// Surprise, if non-zero, makes flow number Surprise (1-based) a connection
	// from "firefox" to a never-before-seen host, so scorers have something to find.
	Surprise int
}

func (s *Synthetic) Name() string { return "synthetic" }

func (s *Synthetic) Run(ctx context.Context, emit func(event.Flow)) error {
	type habit struct {
		prog event.Program
		host string
		ip   string
		port uint16
	}
	habits := []habit{
		{event.Program{Name: "firefox", Path: "/usr/lib/firefox/firefox"}, "example.org", "93.184.216.34", 443},
		{event.Program{Name: "firefox", Path: "/usr/lib/firefox/firefox"}, "cdn.example.org", "93.184.216.35", 443},
		{event.Program{Name: "apt", Path: "/usr/bin/apt"}, "archive.ubuntu.com", "91.189.91.83", 80},
		{event.Program{Name: "chronyd", Path: "/usr/sbin/chronyd"}, "pool.ntp.org", "162.159.200.1", 123},
	}
	t := s.Start
	for i := 1; i <= s.Count; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		h := habits[(i-1)%len(habits)]
		proto := event.TCP
		if h.port == 123 {
			proto = event.UDP
		}
		if s.Surprise != 0 && i == s.Surprise {
			h = habit{habits[0].prog, "evil-c2.example.net", "203.0.113.66", 4444}
			proto = event.TCP
		}
		emit(event.Flow{
			V:           event.SchemaVersion,
			Time:        t,
			Proto:       proto,
			Dir:         event.Outbound,
			Program:     h.prog,
			Local:       netip.MustParseAddrPort("192.168.1.10:50000"),
			Remote:      netip.AddrPortFrom(netip.MustParseAddr(h.ip), h.port),
			DNSName:     h.host,
			BytesIn:     2000,
			BytesOut:    500,
			Packets:     12,
			Established: true,
		})
		t = t.Add(s.Step)
		if s.Sleep > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(s.Sleep):
			}
		}
	}
	return nil
}
