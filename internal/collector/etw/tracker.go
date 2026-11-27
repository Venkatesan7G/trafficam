package etw

import (
	"net/netip"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Windows gives us one event per send and per receive, not one per
// connection. The tracker adds those up and turns them into event.Flow
// values, which is what the rest of trafficam expects:
//
//   - one Flow when a TCP connection closes (disconnect event), or
//   - one Flow when a connection has been quiet for a while (UDP has no
//     "close", and we can miss a TCP disconnect), and
//   - for long-lived connections, an extra Flow every ReportEvery (1 min) with
//     the bytes since the last report, so a download that lasts an hour shows
//     up minute by minute instead of all at the end.

// trackerConfig tunes the tracker. Zero values get the defaults in brackets.
type trackerConfig struct {
	ReportEvery  time.Duration // interim report for long connections [1m]
	IdleUDP      time.Duration // UDP "connection" ends after this much quiet [30s]
	IdleTCP      time.Duration // TCP without a disconnect event ends after [2m]
	MaxConns     int           // memory bound on open connections [65536]
	KeepLoopback bool          // also report 127.0.0.1 <-> 127.0.0.1 traffic [false]
}

func (c *trackerConfig) defaults() {
	if c.ReportEvery <= 0 {
		c.ReportEvery = time.Minute
	}
	if c.IdleUDP <= 0 {
		c.IdleUDP = 30 * time.Second
	}
	if c.IdleTCP <= 0 {
		c.IdleTCP = 2 * time.Minute
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 65536
	}
}

// connKey identifies one socket conversation.
type connKey struct {
	Proto  event.Proto
	PID    uint32
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// conn is what we know so far about one conversation.
type conn struct {
	prog        event.Program
	dir         event.Direction
	dns         string
	first, last time.Time // first and latest event
	reportedAt  time.Time // end of the last reported period (zero = never reported)
	in, out     uint64    // bytes since the last report
	pkts        uint64    // send+receive events since the last report
	gotData     bool      // ever received a byte
	connected   bool      // saw a connect or accept event
	accepted    bool      // saw an accept event
	retried     bool      // saw a retransmit/reconnect
	dirty       bool      // something to report
}

// tracker is not safe for concurrent use; only the worker goroutine uses it.
type tracker struct {
	cfg   trackerConfig
	conns map[connKey]*conn
	names *dnsNames
	// program looks up who owns a PID. It is called once per new connection.
	program func(pid uint32) event.Program
	emit    func(event.Flow)

	Overflow uint64 // events ignored because MaxConns was reached
}

func newTracker(cfg trackerConfig, names *dnsNames, program func(uint32) event.Program, emit func(event.Flow)) *tracker {
	cfg.defaults()
	return &tracker{cfg: cfg, conns: map[connKey]*conn{}, names: names, program: program, emit: emit}
}

// onNet handles one Kernel-Network event.
func (t *tracker) onNet(ev netEvent) {
	if !t.cfg.KeepLoopback && ev.Remote.Addr().IsLoopback() && ev.Local.Addr().IsLoopback() {
		return // traffic that never leaves this PC
	}
	if !ev.Remote.Addr().IsValid() || ev.Remote.Addr().IsUnspecified() {
		return
	}
	k := connKey{ev.Proto, ev.PID, ev.Local, ev.Remote}
	c := t.conns[k]
	if c == nil {
		if ev.Op == opDisconnect {
			return // close of a connection we never saw; nothing to report
		}
		if len(t.conns) >= t.cfg.MaxConns {
			t.Overflow++
			return
		}
		c = &conn{
			prog:  t.program(ev.PID),
			dir:   guessDirection(ev),
			dns:   t.names.lookup(ev.PID, ev.Remote.Addr(), ev.Time),
			first: ev.Time,
		}
		t.conns[k] = c
	}
	c.last = ev.Time
	c.dirty = true
	switch ev.Op {
	case opSend:
		c.out += uint64(ev.Size)
		c.pkts++
	case opRecv:
		c.in += uint64(ev.Size)
		c.pkts++
		if ev.Size > 0 {
			c.gotData = true
		}
	case opConnect:
		c.connected, c.dir = true, event.Outbound
	case opAccept:
		c.connected, c.accepted, c.dir = true, true, event.Inbound
	case opRetransmit, opReconnect:
		c.retried = true
	case opDisconnect:
		t.report(k, c, true)
	}
}

// onDNS handles one finished DNS lookup: remember the answers for labelling
// later connections, and report the lookup itself as a DNS flow.
func (t *tracker) onDNS(ev dnsEvent) {
	if ev.Name == "" {
		return
	}
	if ev.Status == 0 {
		t.names.add(ev.PID, ev.Name, ev.Addrs, ev.Time)
	}
	t.emit(event.Flow{
		V:           event.SchemaVersion,
		Time:        ev.Time,
		Proto:       event.DNS,
		Dir:         event.Outbound,
		Program:     t.program(ev.PID),
		DNSName:     ev.Name,
		Established: ev.Status == 0, // false = lookup failed (e.g. name does not exist)
	})
}

// sweep ends quiet connections and sends interim reports for long ones.
// Call it every few seconds with the current time.
func (t *tracker) sweep(now time.Time) {
	for k, c := range t.conns {
		idle := t.cfg.IdleTCP
		if k.Proto == event.UDP {
			idle = t.cfg.IdleUDP
		}
		switch {
		case now.Sub(c.last) >= idle:
			t.report(k, c, true)
		case c.dirty && now.Sub(c.periodStart()) >= t.cfg.ReportEvery:
			t.report(k, c, false)
		}
	}
}

// flushAll reports everything still open (used on shutdown).
func (t *tracker) flushAll() {
	for k, c := range t.conns {
		t.report(k, c, true)
	}
}

func (c *conn) periodStart() time.Time {
	if c.reportedAt.IsZero() {
		return c.first
	}
	return c.reportedAt
}

// report emits a Flow for the bytes since the last report. If final, the
// connection is forgotten.
func (t *tracker) report(k connKey, c *conn, final bool) {
	if final {
		delete(t.conns, k)
	}
	if !c.dirty {
		return
	}
	if c.dns == "" { // the lookup may have finished after the first packet
		c.dns = t.names.lookup(k.PID, k.Remote.Addr(), c.last)
	}
	t.emit(event.Flow{
		V:           event.SchemaVersion,
		Time:        c.last,
		Proto:       k.Proto,
		Dir:         c.dir,
		Program:     c.prog,
		Local:       k.Local,
		Remote:      k.Remote,
		DNSName:     c.dns,
		BytesIn:     c.in,
		BytesOut:    c.out,
		Packets:     c.pkts,
		Duration:    c.last.Sub(c.periodStart()),
		Established: k.Proto != event.TCP || !c.failed(),
	})
	c.in, c.out, c.pkts, c.dirty = 0, 0, 0, false
	c.reportedAt = c.last
}

// failed reports whether a TCP connection looks like it never got going:
// we had to retry, and the other side never sent us a single byte. This is
// what a port scan, a dead server or a blocked C2 address looks like.
// A connection that was already open when trafficam started (no connect
// event, no retries) is not counted as failed.
func (c *conn) failed() bool {
	return !c.accepted && !c.gotData && c.retried
}

// guessDirection decides who started a conversation from its first event.
// Connect/accept events say it outright. For UDP, or a TCP connection that
// was already open when trafficam started, we fall back on port numbers:
// clients use high "ephemeral" ports (49152+ on Windows), servers low ones.
func guessDirection(ev netEvent) event.Direction {
	switch ev.Op {
	case opConnect:
		return event.Outbound
	case opAccept:
		return event.Inbound
	}
	lp, rp := ev.Local.Port(), ev.Remote.Port()
	const ephemeral = 49152
	if lp < ephemeral && rp >= ephemeral {
		return event.Inbound
	}
	if lp >= ephemeral && rp < ephemeral {
		return event.Outbound
	}
	if ev.Proto == event.UDP && ev.Op == opRecv {
		return event.Inbound // first thing we saw was someone sending to us
	}
	return event.Outbound
}
