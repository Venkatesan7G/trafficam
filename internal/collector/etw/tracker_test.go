package etw

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// rawV4 builds a Kernel-Network IPv4 payload the way Windows lays it out.
func rawV4(pid, size uint32, remote, local netip.AddrPort) []byte {
	b := make([]byte, 0, 28)
	b = binary.LittleEndian.AppendUint32(b, pid)
	b = binary.LittleEndian.AppendUint32(b, size)
	r, l := remote.Addr().As4(), local.Addr().As4()
	b = append(b, r[:]...)
	b = append(b, l[:]...)
	b = binary.BigEndian.AppendUint16(b, remote.Port())
	b = binary.BigEndian.AppendUint16(b, local.Port())
	return append(b, make([]byte, 8)...) // seqnum, connid: present on the wire, unused
}

func TestParseKernelNetworkV4(t *testing.T) {
	rem := netip.MustParseAddrPort("93.184.216.34:443")
	loc := netip.MustParseAddrPort("192.168.1.10:51000")
	now := time.Unix(1700000000, 0)
	ev, ok := parseKernelNetwork(10, rawV4(1234, 517, rem, loc), now)
	if !ok {
		t.Fatal("not parsed")
	}
	if ev.Op != opSend || ev.Proto != event.TCP || ev.PID != 1234 || ev.Size != 517 || ev.Remote != rem || ev.Local != loc {
		t.Fatalf("bad parse: %+v", ev)
	}
	if _, ok := parseKernelNetwork(10, make([]byte, 10), now); ok {
		t.Fatal("short payload accepted")
	}
	if _, ok := parseKernelNetwork(17, rawV4(1, 1, rem, loc), now); ok {
		t.Fatal("unused event id accepted")
	}
}

func TestParseKernelNetworkV6(t *testing.T) {
	rem := netip.MustParseAddrPort("[2606:2800:220:1::1]:443")
	loc := netip.MustParseAddrPort("[fe80::1]:50000")
	b := binary.LittleEndian.AppendUint32(nil, 7)
	b = binary.LittleEndian.AppendUint32(b, 100)
	r, l := rem.Addr().As16(), loc.Addr().As16()
	b = append(b, r[:]...)
	b = append(b, l[:]...)
	b = binary.BigEndian.AppendUint16(b, rem.Port())
	b = binary.BigEndian.AppendUint16(b, loc.Port())
	ev, ok := parseKernelNetwork(59, b, time.Now()) // UDP receive IPv6
	if !ok || ev.Op != opRecv || ev.Proto != event.UDP || ev.Remote != rem || ev.Local != loc || ev.PID != 7 {
		t.Fatalf("bad parse: %+v ok=%v", ev, ok)
	}
}

func TestParseDNSResults(t *testing.T) {
	got := parseDNSResults("type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;;junk;")
	want := []string{"93.184.216.34", "2606:2800::1"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if cleanDNSName(" Example.ORG. ") != "example.org" {
		t.Fatal("cleanDNSName")
	}
}

func TestFiletime(t *testing.T) {
	// 2026-01-01T00:00:00Z in FILETIME ticks.
	ft := int64(116444736000000000) + time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()*10_000_000
	if got := filetimeToTime(ft); !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal(got)
	}
}

type harness struct {
	flows []event.Flow
	tr    *tracker
}

func newHarness(cfg trackerConfig) *harness {
	h := &harness{}
	prog := func(pid uint32) event.Program {
		return event.Program{PID: int(pid), Name: "app.exe", Path: `C:\app.exe`}
	}
	h.tr = newTracker(cfg, newDNSNames(0, 0), prog, func(f event.Flow) { h.flows = append(h.flows, f) })
	return h
}

func TestTrackerTCPLifecycleWithDNSName(t *testing.T) {
	h := newHarness(trackerConfig{})
	t0 := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	rem := netip.MustParseAddrPort("93.184.216.34:443")
	loc := netip.MustParseAddrPort("192.168.1.10:51000")

	h.tr.onDNS(dnsEvent{PID: 42, Name: "example.org", Addrs: []netip.Addr{rem.Addr()}, Time: t0})
	ev := func(op netOp, size uint32, dt time.Duration) {
		h.tr.onNet(netEvent{Op: op, Proto: event.TCP, PID: 42, Size: size, Local: loc, Remote: rem, Time: t0.Add(dt)})
	}
	ev(opConnect, 0, time.Second)
	ev(opSend, 300, 2*time.Second)
	ev(opRecv, 5000, 3*time.Second)
	ev(opRecv, 1000, 4*time.Second)
	ev(opDisconnect, 0, 5*time.Second)

	if len(h.flows) != 2 {
		t.Fatalf("want DNS flow + TCP flow, got %d: %+v", len(h.flows), h.flows)
	}
	d, f := h.flows[0], h.flows[1]
	if d.Proto != event.DNS || d.DNSName != "example.org" || !d.Established {
		t.Fatalf("dns flow: %+v", d)
	}
	if f.Proto != event.TCP || f.Dir != event.Outbound || f.DNSName != "example.org" ||
		f.BytesOut != 300 || f.BytesIn != 6000 || f.Packets != 3 || !f.Established ||
		f.Duration != 4*time.Second || f.Program.PID != 42 || f.V != event.SchemaVersion {
		t.Fatalf("tcp flow: %+v", f)
	}
	if len(h.tr.conns) != 0 {
		t.Fatal("connection not forgotten after disconnect")
	}
}

func TestTrackerFailedConnect(t *testing.T) {
	h := newHarness(trackerConfig{})
	t0 := time.Now()
	rem := netip.MustParseAddrPort("203.0.113.66:4444")
	loc := netip.MustParseAddrPort("192.168.1.10:52000")
	h.tr.onNet(netEvent{Op: opReconnect, Proto: event.TCP, PID: 9, Local: loc, Remote: rem, Time: t0})
	h.tr.onNet(netEvent{Op: opRetransmit, Proto: event.TCP, PID: 9, Local: loc, Remote: rem, Time: t0.Add(3 * time.Second)})
	h.tr.sweep(t0.Add(10 * time.Minute))
	if len(h.flows) != 1 || h.flows[0].Established || h.flows[0].Dir != event.Outbound {
		t.Fatalf("want one failed outbound flow, got %+v", h.flows)
	}
}

func TestTrackerInterimAndUDPIdle(t *testing.T) {
	h := newHarness(trackerConfig{})
	t0 := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	rem := netip.MustParseAddrPort("162.159.200.1:123")
	loc := netip.MustParseAddrPort("192.168.1.10:60000")
	for i := 0; i < 90; i++ { // one packet a second for 90 s
		h.tr.onNet(netEvent{Op: opSend, Proto: event.UDP, PID: 5, Size: 48, Local: loc, Remote: rem, Time: t0.Add(time.Duration(i) * time.Second)})
		h.tr.sweep(t0.Add(time.Duration(i) * time.Second))
	}
	if len(h.flows) != 1 {
		t.Fatalf("want one interim report after a minute, got %d", len(h.flows))
	}
	h.tr.sweep(t0.Add(3 * time.Minute)) // quiet for > 30 s: ends
	if len(h.flows) != 2 || len(h.tr.conns) != 0 {
		t.Fatalf("want final report, got %d flows, %d open", len(h.flows), len(h.tr.conns))
	}
	var total uint64
	for _, f := range h.flows {
		total += f.BytesOut
		if f.Dir != event.Outbound || f.Proto != event.UDP {
			t.Fatalf("bad flow %+v", f)
		}
	}
	if total != 90*48 {
		t.Fatalf("bytes lost or double counted: %d", total)
	}
}

func TestTrackerLoopbackAndLimits(t *testing.T) {
	h := newHarness(trackerConfig{MaxConns: 1})
	lo := netip.MustParseAddrPort("127.0.0.1:5000")
	h.tr.onNet(netEvent{Op: opSend, Proto: event.TCP, PID: 1, Size: 1, Local: lo, Remote: lo, Time: time.Now()})
	if len(h.tr.conns) != 0 {
		t.Fatal("loopback should be ignored by default")
	}
	a := netip.MustParseAddrPort("192.168.1.10:50000")
	h.tr.onNet(netEvent{Op: opSend, Proto: event.TCP, PID: 1, Size: 1, Local: a, Remote: netip.MustParseAddrPort("1.1.1.1:443"), Time: time.Now()})
	h.tr.onNet(netEvent{Op: opSend, Proto: event.TCP, PID: 1, Size: 1, Local: a, Remote: netip.MustParseAddrPort("1.0.0.1:443"), Time: time.Now()})
	if len(h.tr.conns) != 1 || h.tr.Overflow != 1 {
		t.Fatalf("MaxConns not enforced: %d open, overflow %d", len(h.tr.conns), h.tr.Overflow)
	}
	h.tr.flushAll()
	if len(h.flows) != 1 || len(h.tr.conns) != 0 {
		t.Fatal("flushAll")
	}
}

func TestGuessDirection(t *testing.T) {
	in := netEvent{Op: opRecv, Proto: event.TCP, Local: netip.MustParseAddrPort("10.0.0.2:3389"), Remote: netip.MustParseAddrPort("10.0.0.9:51515")}
	if guessDirection(in) != event.Inbound {
		t.Fatal("RDP server side should be inbound")
	}
	out := netEvent{Op: opSend, Proto: event.TCP, Local: netip.MustParseAddrPort("10.0.0.2:51515"), Remote: netip.MustParseAddrPort("1.1.1.1:443")}
	if guessDirection(out) != event.Outbound {
		t.Fatal("client side should be outbound")
	}
}

func TestDNSNamesPerProcessFirst(t *testing.T) {
	d := newDNSNames(time.Minute, 10)
	now := time.Now()
	ip := netip.MustParseAddr("1.2.3.4")
	d.add(1, "a.example", []netip.Addr{ip}, now)
	d.add(2, "b.example", []netip.Addr{ip}, now)
	if d.lookup(1, ip, now) != "a.example" || d.lookup(2, ip, now) != "b.example" {
		t.Fatal("per-process answer should win")
	}
	if d.lookup(3, ip, now) != "b.example" {
		t.Fatal("global fallback should be the latest answer")
	}
	if d.lookup(1, ip, now.Add(2*time.Minute)) != "" {
		t.Fatal("entries should expire")
	}
	d.forget(1)
	if d.count != 1 {
		t.Fatalf("count %d", d.count)
	}
	for i := 0; i < 50; i++ { // stays bounded
		d.add(uint32(i), "x", []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, now)
	}
	if d.count > 10 || len(d.global) > 10 {
		t.Fatalf("not bounded: %d %d", d.count, len(d.global))
	}
}

// sockaddrIn builds a Windows sockaddr_in / sockaddr_in6 with its length prefix.
func sockaddrIn(ap netip.AddrPort) []byte {
	var sa []byte
	if ap.Addr().Is4() {
		sa = make([]byte, 16)
		binary.LittleEndian.PutUint16(sa[0:2], 2)
		a := ap.Addr().As4()
		copy(sa[4:8], a[:])
	} else {
		sa = make([]byte, 28)
		binary.LittleEndian.PutUint16(sa[0:2], 23)
		a := ap.Addr().As16()
		copy(sa[8:24], a[:])
	}
	binary.BigEndian.PutUint16(sa[2:4], ap.Port())
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(sa))), sa...)
}

// rawConnectFail builds a TCPIP event 1034 (version 1) payload.
func rawConnectFail(local, remote netip.AddrPort, status, pid uint32) []byte {
	b := append(sockaddrIn(local), sockaddrIn(remote)...)
	b = binary.LittleEndian.AppendUint32(b, status)
	b = binary.LittleEndian.AppendUint32(b, pid)
	b = binary.LittleEndian.AppendUint32(b, 1)        // compartment
	b = binary.LittleEndian.AppendUint64(b, 0xfeed)   // Tcb pointer
	return binary.LittleEndian.AppendUint64(b, 12345) // ProcessStartKey (v1)
}

func TestParseTCPConnectFail(t *testing.T) {
	for _, tc := range []struct{ local, remote string }{
		{"192.168.1.10:51000", "203.0.113.5:4444"},
		{"[2001:db8::10]:51000", "[2001:db8::5]:4444"},
	} {
		loc, rem := netip.MustParseAddrPort(tc.local), netip.MustParseAddrPort(tc.remote)
		ev, ok := parseTCPConnectFail(rawConnectFail(loc, rem, statusConnectionRefused, 321), time.Now())
		if !ok || ev.Op != opConnectFail || ev.Proto != event.TCP || ev.PID != 321 ||
			ev.Local != loc || ev.Remote != rem || ev.Size != statusConnectionRefused {
			t.Fatalf("%s: bad parse %+v ok=%v", tc.remote, ev, ok)
		}
	}
	full := rawConnectFail(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"), 0, 1)
	for n := 0; n < 4+16+4+16+8; n++ { // every truncation before the PID must be rejected, never panic
		if _, ok := parseTCPConnectFail(full[:n], time.Now()); ok {
			t.Fatalf("accepted a payload cut to %d bytes", n)
		}
	}
	bad := append([]byte(nil), full...)
	binary.LittleEndian.PutUint32(bad[0:4], 1<<30) // absurd length
	if _, ok := parseTCPConnectFail(bad, time.Now()); ok {
		t.Fatal("accepted absurd address length")
	}
}

func TestTrackerRefusedConnection(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	loc := netip.MustParseAddrPort("192.168.1.10:51000")
	rem := netip.MustParseAddrPort("203.0.113.5:4444")

	// Refused straight away: Kernel-Network said nothing, only event 1034.
	h := newHarness(trackerConfig{})
	h.tr.onNet(netEvent{Op: opConnectFail, Proto: event.TCP, PID: 9, Local: loc, Remote: rem, Size: statusConnectionRefused, Time: t0})
	if len(h.flows) != 1 || h.flows[0].Established || h.flows[0].Dir != event.Outbound || h.flows[0].Remote != rem {
		t.Fatalf("want one failed outbound flow, got %+v", h.flows)
	}
	if len(h.tr.conns) != 0 {
		t.Fatal("failed attempt should be forgotten")
	}

	// Windows retried first (Kernel-Network reconnect events), then gave up.
	// Must be ONE failed flow, reported at once, not a second one later.
	h = newHarness(trackerConfig{})
	h.tr.onNet(netEvent{Op: opReconnect, Proto: event.TCP, PID: 9, Local: loc, Remote: rem, Time: t0})
	h.tr.onNet(netEvent{Op: opConnectFail, Proto: event.TCP, PID: 9, Local: netip.AddrPortFrom(netip.IPv4Unspecified(), 0), Remote: rem, Time: t0.Add(2 * time.Second)})
	h.tr.sweep(t0.Add(10 * time.Minute))
	if len(h.flows) != 1 || h.flows[0].Established || h.flows[0].Local != loc {
		t.Fatalf("want one failed flow from %v, got %+v", loc, h.flows)
	}
}
