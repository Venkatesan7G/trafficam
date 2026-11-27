//go:build linux

package linuxebpf

// tracker.go turns kernel events and counters into event.Flow values.

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

var kernelSpec = sync.OnceValues(btf.LoadKernelSpec)

type tracker struct {
	cfg   Config
	procs *procResolver
	names *nameCache

	// The core's emit is called from several goroutines here; the mutex
	// keeps calls one at a time so emit never has to be thread-safe.
	emitMu sync.Mutex
	emitFn func(event.Flow)

	// eBPF maps shared with the kernel side.
	udpFlows *ebpf.Map
	udpOwner *ebpf.Map
	conns    *ebpf.Map

	// connState reads the kernel's conns table entry for a TCP socket:
	// ok=false if it is no longer tracked. A field so unit tests can fake it.
	connState func(sk uint64) (kc trafficamConn, ok bool)
	// dnsRetry is how long to wait before each new look at udp_owner when
	// a DNS question's sender is not known yet.
	dnsRetry []time.Duration
	// ownerLookup replaces the udp_owner map in unit tests.
	ownerLookup func(port uint16) (trafficamOwner, bool)

	dnsActive atomic.Bool

	mu        sync.Mutex
	open      map[uint64]*openConn           // TCP connections seen opening, by socket id
	udpSeen   map[trafficamUdpKey]*udpReport // what we already reported per UDP peer
	lsnOwners map[uint16]procFacts           // fallback owners of listening ports
	lsnScan   time.Time
	nowWall   func() time.Time
	nowBoot   func() uint64
}

// openConn is a TCP connection between its open and close events.
type openConn struct {
	prog     event.Program
	pid      int
	dir      event.Direction
	local    netip.AddrPort
	remote   netip.AddrPort
	startNs  uint64
	reported bool   // already sent once because it stayed open long
	repNs    uint64 // kernel time the early report covered up to
}

type udpReport struct {
	bytesIn, bytesOut, pktsIn, pktsOut uint64
	lastNs                             uint64    // kernel time covered so far
	lastEmit                           time.Time // wall time of the last report
}

func newTracker(cfg Config, emit func(event.Flow)) *tracker {
	cgRoot := findCgroup2Mount("/proc/self/mountinfo")
	return &tracker{
		cfg:     cfg,
		procs:   newProcResolver("/proc", cgRoot),
		names:   newNameCache(65536),
		emitFn:  emit,
		open:    map[uint64]*openConn{},
		udpSeen: map[trafficamUdpKey]*udpReport{},
		nowWall: time.Now,
		nowBoot: boottimeNow,
		// The kernel writes udp_owner when the send returns, which is
		// normally microseconds after we read the packet; the later steps
		// cover a busy or preempted machine.
		dnsRetry: []time.Duration{20 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond},
	}
}

// kernelConnState reads one entry of the kernel's conns table.
func (t *tracker) kernelConnState(sk uint64) (kc trafficamConn, ok bool) {
	return kc, t.conns.Lookup(sk, &kc) == nil
}

func (t *tracker) emit(f event.Flow) {
	f.V = event.SchemaVersion
	t.emitMu.Lock()
	defer t.emitMu.Unlock()
	t.emitFn(f)
}

// wallTime converts a kernel boot-clock timestamp to wall-clock time.
func (t *tracker) wallTime(ns uint64) time.Time {
	now := t.nowBoot()
	if ns == 0 || ns > now {
		return t.nowWall()
	}
	return t.nowWall().Add(-time.Duration(now - ns))
}

// program builds the event.Program for a socket owner captured in the kernel.
func (t *tracker) program(o trafficamOwner) event.Program {
	if o.Tgid == 0 {
		return event.Program{Name: "kernel"}
	}
	info := t.procs.Resolve(procFacts{
		PID: int(o.Tgid), PPID: int(o.Ppid), Cgroup: o.Cgroup,
		Comm: cString(o.Comm[:]), PComm: cString(o.Pcomm[:]),
	})
	p := event.Program{PID: int(o.Tgid), Name: info.Name, Path: info.Path, Parent: info.Parent}
	setUnit(&p, info.Unit)
	return p
}

// listenerOwner finds the owner of a listening port through /proc. The
// scan is cached and repeated at most every 10 seconds.
func (t *tracker) listenerOwner(port uint16) trafficamOwner {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.lsnOwners[port]
	if !ok && t.nowWall().Sub(t.lsnScan) >= 10*time.Second {
		t.lsnScan = t.nowWall()
		t.lsnOwners = listenerOwners(t.procs.Root)
		f, ok = t.lsnOwners[port]
	}
	if !ok {
		return trafficamOwner{}
	}
	return toOwner(f)
}

func (t *tracker) skip(remote netip.Addr) bool {
	return !t.cfg.IncludeLoopback && remote.IsLoopback()
}

func (t *tracker) handleEvent(ev *trafficamEvent) {
	local := netip.AddrPortFrom(toAddr(ev.Family, ev.Saddr), ev.Sport)
	remote := netip.AddrPortFrom(toAddr(ev.Family, ev.Daddr), ev.Dport)
	dir := event.Outbound
	if ev.Dir == dirIn {
		dir = event.Inbound
	}

	switch ev.Kind {
	case evUDPOpen:
		// Resolve now, while the process surely still exists, so the
		// details are cached for when its counters are reported.
		t.program(ev.O)

	case evTCPOpen:
		if t.skip(remote.Addr()) {
			return
		}
		o := ev.O
		if o.Tgid == 0 && dir == event.Inbound {
			o = t.listenerOwner(ev.Sport) // server started before we did
		}
		c := &openConn{prog: t.program(o), pid: int(o.Tgid), dir: dir, local: local, remote: remote, startNs: ev.StartNs}
		t.mu.Lock()
		if len(t.open) < 1<<17 { // hard bound on memory
			t.open[ev.Sk] = c
		}
		t.mu.Unlock()

	case evTCPClose:
		if t.skip(remote.Addr()) {
			return
		}
		t.mu.Lock()
		c := t.open[ev.Sk]
		delete(t.open, ev.Sk)
		t.mu.Unlock()
		prog := event.Program{}
		if c != nil {
			prog = c.prog
		} else {
			prog = t.program(ev.O) // open event was lost; best effort
		}
		startNs := ev.StartNs
		cont := c != nil && c.reported
		if cont {
			// Already reported once while open (and counted then). This
			// report carries the totals and only the time since then, so
			// the connection counts once and its time adds up right.
			startNs = c.repNs
		}
		f := event.Flow{
			Time:        t.wallTime(ev.EndNs),
			Proto:       event.TCP,
			Dir:         dir,
			Program:     prog,
			Local:       local,
			Remote:      remote,
			DNSName:     t.names.Lookup(int(ev.O.Tgid), remote.Addr()),
			BytesIn:     ev.BytesIn,
			BytesOut:    ev.BytesOut,
			Packets:     ev.PktsIn + ev.PktsOut,
			Established: ev.Established != 0,
			Cont:        cont,
		}
		if ev.EndNs > startNs && startNs != 0 {
			f.Duration = time.Duration(ev.EndNs - startNs)
		}
		t.emit(f)
	}
}

func (t *tracker) sweepLoop(ctx context.Context) {
	tick := time.NewTicker(t.cfg.SweepEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.sweepUDP(true) // report what we have before stopping
			return
		case <-tick.C:
			t.sweepTCP()
			t.sweepUDP(false)
		}
	}
}

// sweepTCP reports connections that have been open longer than
// TCPReportAfter, once, and forgets ones the kernel no longer tracks.
func (t *tracker) sweepTCP() {
	now := t.nowBoot()
	var due []*openConn
	var dueKC []trafficamConn
	state := t.connState
	if state == nil {
		state = t.kernelConnState
	}
	t.mu.Lock()
	for sk, c := range t.open {
		kc, ok := state(sk)
		if !ok {
			delete(t.open, sk) // close event was lost or entry evicted
			continue
		}
		if !c.reported && now-c.startNs >= uint64(t.cfg.TCPReportAfter) {
			c.reported = true
			c.repNs = now
			due = append(due, c)
			dueKC = append(dueKC, kc)
		}
	}
	t.mu.Unlock()
	for i, c := range due {
		local := c.local
		if local.Port() == 0 && dueKC[i].Lport != 0 {
			// connect() had not picked a local port yet when the open
			// event was sent; the kernel saved it once established.
			fam := uint8(unix.AF_INET6)
			if c.remote.Addr().Is4() {
				fam = unix.AF_INET
			}
			local = netip.AddrPortFrom(toAddr(fam, dueKC[i].Laddr), dueKC[i].Lport)
		}
		t.emit(event.Flow{
			Time: t.nowWall(), Proto: event.TCP, Dir: c.dir, Program: c.prog,
			Local: local, Remote: c.remote,
			DNSName:     t.names.Lookup(c.pid, c.remote.Addr()),
			Established: dueKC[i].Established != 0,
			Duration:    time.Duration(now - c.startNs),
		})
	}
}

// sweepUDP reads the kernel's UDP counter table and reports changes:
// immediately for a new peer, then every UDPReportEvery while active, and
// a final report when the peer goes quiet (the entry is then deleted).
func (t *tracker) sweepUDP(final bool) {
	now := t.nowBoot()
	wall := t.nowWall()
	var (
		k       trafficamUdpKey
		v       trafficamUdpVal
		present = map[trafficamUdpKey]bool{}
		remove  []trafficamUdpKey
		out     []event.Flow
	)
	it := t.udpFlows.Iterate()
	for it.Next(&k, &v) {
		present[k] = true
		idle := now > v.LastNs && now-v.LastNs >= uint64(t.cfg.UDPIdle)
		r := t.udpSeen[k]
		isNew := r == nil
		if isNew {
			r = &udpReport{lastNs: v.FirstNs}
			t.udpSeen[k] = r
		}
		changed := v.BytesIn != r.bytesIn || v.BytesOut != r.bytesOut
		due := isNew || idle || final || wall.Sub(r.lastEmit) >= t.cfg.UDPReportEvery
		if changed && due {
			if f, ok := t.udpFlow(k, v, r); ok {
				out = append(out, f)
			}
			r.bytesIn, r.bytesOut, r.pktsIn, r.pktsOut = v.BytesIn, v.BytesOut, v.PktsIn, v.PktsOut
			r.lastNs, r.lastEmit = v.LastNs, wall
		}
		if idle {
			remove = append(remove, k)
		}
	}
	for _, k := range remove {
		_ = t.udpFlows.Delete(k) // a packet racing this delete starts a fresh entry
		delete(t.udpSeen, k)
	}
	for k := range t.udpSeen {
		if !present[k] {
			delete(t.udpSeen, k) // evicted by the kernel's LRU map
		}
	}
	for _, f := range out {
		t.emit(f)
	}
}

// udpFlow builds the flow for the counters added since the last report.
func (t *tracker) udpFlow(k trafficamUdpKey, v trafficamUdpVal, r *udpReport) (event.Flow, bool) {
	fam := uint8(k.Family)
	remote := netip.AddrPortFrom(toAddr(fam, k.Raddr), k.Rport)
	if t.skip(remote.Addr()) {
		return event.Flow{}, false
	}
	if k.Rport == 53 && t.dnsActive.Load() {
		return event.Flow{}, false // reported as DNS lookups instead
	}
	dir := event.Outbound
	if v.Dir == dirIn {
		dir = event.Inbound
	}
	f := event.Flow{
		Time:     t.wallTime(v.LastNs),
		Proto:    event.UDP,
		Dir:      dir,
		Program:  t.program(v.O),
		Local:    netip.AddrPortFrom(toAddr(fam, v.Laddr), v.Lport),
		Remote:   remote,
		DNSName:  t.names.Lookup(int(v.O.Tgid), remote.Addr()),
		BytesIn:  v.BytesIn - r.bytesIn,
		BytesOut: v.BytesOut - r.bytesOut,
		Packets:  (v.PktsIn - r.pktsIn) + (v.PktsOut - r.pktsOut),
	}
	if v.LastNs > r.lastNs {
		f.Duration = time.Duration(v.LastNs - r.lastNs)
	}
	return f, true
}

// dnsLoop reads DNS packets from a passive packet socket until ctx ends.
func (t *tracker) dnsLoop(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := attachFilter(fd); err != nil {
		return err
	}
	// Wake up every second to notice ctx being cancelled.
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	t.dnsActive.Store(true)
	loop := loopbackIndexes()
	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return err
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		outgoing := ll.Pkttype == unix.PACKET_OUTGOING
		// On loopback every packet shows up twice (once leaving, once
		// arriving). Keep only the arriving copy.
		if loop[ll.Ifindex] {
			if outgoing {
				continue
			}
			outgoing = true // a local program sent it; treat as "sent by us"
		}
		p, ok := parseDNSPacket(buf[:n])
		if !ok {
			continue
		}
		t.handleDNS(p, outgoing, loop[ll.Ifindex], n)
	}
	return nil
}

// handleDNS turns one DNS packet into a lookup flow (questions sent by a
// program on this PC) or name-cache entries (answers it received).
func (t *tracker) handleDNS(p dnsPacket, outgoing, loopback bool, size int) {
	switch {
	case !p.Response && p.Dst.Port() == 53 && outgoing:
		// A program here asked a question. Its owner is in udp_owner,
		// written by the kernel when the send returns. We can read the
		// packet a moment before that, so look again a few times.
		t.dnsOwnerThen(p.Src.Port(), 0, func(o trafficamOwner) { t.emitDNS(p, o, size) })

	case p.Response && p.Src.Port() == 53 && (!outgoing || loopback):
		// An answer for a program here: remember which name each address
		// came from so later connections can be labelled.
		pid := 0
		if o, ok := t.ownerOfPort(p.Dst.Port()); ok {
			pid = int(o.Tgid)
		}
		for _, ip := range p.Answers {
			t.names.Put(pid, ip, p.Name, p.TTL)
		}
	}
}

// dnsOwnerThen calls fn with the owner of a local UDP port, waiting for
// the kernel to record it if needed (t.dnsRetry). After the last try fn
// gets an empty owner, and the lookup is reported as "unknown".
func (t *tracker) dnsOwnerThen(port uint16, try int, fn func(trafficamOwner)) {
	if o, ok := t.ownerOfPort(port); ok || try >= len(t.dnsRetry) {
		fn(o)
		return
	}
	time.AfterFunc(t.dnsRetry[try], func() { t.dnsOwnerThen(port, try+1, fn) })
}

func (t *tracker) emitDNS(p dnsPacket, o trafficamOwner, size int) {
	prog := event.Program{Name: "unknown"} // still reported: we never hide traffic
	if o.Tgid != 0 {
		prog = t.program(o)
	}
	t.emit(event.Flow{
		Time: t.nowWall(), Proto: event.DNS, Dir: event.Outbound, Program: prog,
		Local: p.Src, Remote: p.Dst, DNSName: p.Name,
		BytesOut: uint64(size), Packets: 1,
	})
}

func (t *tracker) ownerOfPort(port uint16) (trafficamOwner, bool) {
	var o trafficamOwner
	if t.ownerLookup != nil {
		return t.ownerLookup(port)
	}
	if t.udpOwner == nil {
		return o, false
	}
	err := t.udpOwner.Lookup(port, &o)
	return o, err == nil
}

func attachFilter(fd int) error {
	raw, err := dnsFilter()
	if err != nil {
		return err
	}
	filt := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filt[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filt)), Filter: &filt[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

func loopbackIndexes() map[int]bool {
	m := map[int]bool{1: true} // "lo" is index 1 on Linux
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			m[i.Index] = true
		}
	}
	return m
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
