package aggregate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func flow(t time.Time, host string, est bool) event.Flow {
	return event.Flow{V: 1, Time: t, Proto: event.TCP, Dir: event.Outbound,
		Program: event.Program{Name: "p", Path: "/bin/p"}, DNSName: host,
		Remote: netip.MustParseAddrPort("1.2.3.4:443"), BytesIn: 10, BytesOut: 5, Packets: 2, Established: est}
}

func TestMergesWithinMinuteAndClosesByEventTime(t *testing.T) {
	a := New()
	t0 := time.Date(2026, 1, 1, 9, 0, 10, 0, time.UTC)
	a.Add(flow(t0, "a.com", true))
	a.Add(flow(t0.Add(20*time.Second), "a.com", false))
	a.Add(flow(t0.Add(5*time.Second), "b.com", true))
	if got := a.CloseByEventTime(time.Minute); len(got) != 0 {
		t.Fatalf("nothing should close yet, got %d", len(got))
	}
	// An event 3 minutes later pushes the 09:00 minute past the grace period.
	a.Add(flow(t0.Add(3*time.Minute), "a.com", true))
	got := a.CloseByEventTime(time.Minute)
	if len(got) != 2 {
		t.Fatalf("want 2 closed rows, got %d", len(got))
	}
	var m event.Minute
	for _, r := range got {
		if r.Host == "a.com" {
			m = r
		}
	}
	if m.Flows != 2 || m.BytesIn != 20 || m.FailedCount != 1 || !m.Start.Equal(t0.Truncate(time.Minute)) {
		t.Fatalf("bad merge: %+v", m)
	}
	if rest := a.Drain(); len(rest) != 1 {
		t.Fatalf("drain want 1, got %d", len(rest))
	}
}
