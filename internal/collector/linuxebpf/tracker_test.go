//go:build linux

package linuxebpf

import (
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Venkatesan7G/trafficam/internal/aggregate"
	"github.com/Venkatesan7G/trafficam/internal/event"
)

// testTracker returns a tracker with a fake kernel clock and a fake conns
// table, collecting what it emits.
func testTracker(t *testing.T) (*tracker, *uint64, *[]event.Flow) {
	t.Helper()
	var flows []event.Flow
	tr := newTracker(Config{TCPReportAfter: 30 * time.Second}, func(f event.Flow) { flows = append(flows, f) })
	boot := uint64(1e12)
	tr.nowBoot = func() uint64 { return boot }
	wall := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	tr.nowWall = func() time.Time { return wall.Add(time.Duration(boot - 1e12)) }
	tr.connState = func(uint64) (trafficamConn, bool) {
		kc := trafficamConn{Established: 1, Lport: 50000}
		copy(kc.Laddr[:], []byte{192, 168, 1, 10})
		return kc, true
	}
	return tr, &boot, &flows
}

func tcpEvent(kind uint8, sk, startNs, endNs uint64) *trafficamEvent {
	ev := &trafficamEvent{Sk: sk, Kind: kind, Family: unix.AF_INET, Dir: dirOut, StartNs: startNs, EndNs: endNs, Established: 1}
	copy(ev.Saddr[:], []byte{192, 168, 1, 10})
	copy(ev.Daddr[:], []byte{93, 184, 216, 34})
	ev.Dport = 443
	if kind == evTCPClose {
		ev.Sport = 50000
	} else {
		ev.Saddr = [16]uint8{} // connect() has not picked a local address yet
	}
	return ev
}

// A connection open longer than TCPReportAfter is reported early, then
// again with its totals when it closes. Both reports together must count as
// ONE connection, with its real length.
func TestLongTCPCountsOnce(t *testing.T) {
	tr, boot, flows := testTracker(t)
	start := *boot
	tr.handleEvent(tcpEvent(evTCPOpen, 7, start, 0))
	*boot += uint64(31 * time.Second)
	tr.sweepTCP()
	*boot += uint64(69 * time.Second)
	tr.sweepTCP() // must not report it a second time while still open
	closeEv := tcpEvent(evTCPClose, 7, start, *boot)
	closeEv.BytesIn, closeEv.BytesOut = 5000, 700
	tr.handleEvent(closeEv)

	if len(*flows) != 2 {
		t.Fatalf("want 2 reports (early + close), got %d: %+v", len(*flows), *flows)
	}
	early, last := (*flows)[0], (*flows)[1]
	if early.Local.String() != "192.168.1.10:50000" {
		t.Errorf("early report local = %v, want the kernel's saved local address", early.Local)
	}
	if early.Cont || !last.Cont {
		t.Fatalf("Cont = %v, %v; want false, true", early.Cont, last.Cont)
	}
	if early.Duration != 31*time.Second || last.Duration != 69*time.Second {
		t.Fatalf("durations %v + %v, want 31s + 69s", early.Duration, last.Duration)
	}
	if last.BytesIn != 5000 || last.BytesOut != 700 {
		t.Fatalf("totals lost: %+v", last)
	}

	a := aggregate.New()
	for _, f := range *flows {
		f.Time = time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC) // same minute
		a.Add(f)
	}
	rows := a.Drain()
	if len(rows) != 1 || rows[0].Flows != 1 || rows[0].DurationMs != 100000 {
		t.Fatalf("want 1 row, Flows=1, DurationMs=100000; got %+v", rows)
	}
}

func TestShortTCPNotCont(t *testing.T) {
	tr, boot, flows := testTracker(t)
	start := *boot
	tr.handleEvent(tcpEvent(evTCPOpen, 8, start, 0))
	*boot += uint64(2 * time.Second)
	tr.sweepTCP()
	tr.handleEvent(tcpEvent(evTCPClose, 8, start, *boot))
	if len(*flows) != 1 || (*flows)[0].Cont || (*flows)[0].Duration != 2*time.Second {
		t.Fatalf("want one 2s flow, not Cont; got %+v", *flows)
	}
}

// The DNS sender's owner may appear in udp_owner a moment after we read the
// packet: keep looking for a while, then give up with "unknown".
func TestDNSOwnerRetry(t *testing.T) {
	tr, _, _ := testTracker(t)
	tr.dnsRetry = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}

	var calls atomic.Int32
	tr.ownerLookup = func(uint16) (trafficamOwner, bool) {
		if calls.Add(1) < 3 {
			return trafficamOwner{}, false
		}
		return trafficamOwner{Tgid: 42}, true
	}
	got := make(chan trafficamOwner, 1)
	tr.dnsOwnerThen(5353, 0, func(o trafficamOwner) { got <- o })
	select {
	case o := <-got:
		if o.Tgid != 42 {
			t.Fatalf("owner = %d, want 42", o.Tgid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no answer")
	}

	calls.Store(-100) // never found
	tr.dnsOwnerThen(5353, 0, func(o trafficamOwner) { got <- o })
	select {
	case o := <-got:
		if o.Tgid != 0 {
			t.Fatalf("owner = %d, want none", o.Tgid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gave up without calling back")
	}
}
