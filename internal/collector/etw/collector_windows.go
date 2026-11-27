//go:build windows && (amd64 || arm64)

package etw

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Collector is the Windows ETW capture layer. It implements
// collector.Collector. The zero value is ready to use.
//
// It needs administrator rights (or to run as the trafficam Windows service,
// which runs as LocalSystem). It is passive: it only reads ETW events.
type Collector struct {
	SessionName  string        // ETW session name (default "trafficam"; must be unique on the machine)
	QueueSize    int           // events waiting between the ETW thread and the worker (default 16384)
	KeepLoopback bool          // also report traffic to 127.0.0.1 / ::1 (default off)
	Log          *slog.Logger  // default slog.Default()
	StatsEvery   time.Duration // how often to log counters (default 10 min; <0 = never)

	Stats Stats

	// checkLayout, set by tests, double-checks every network event's
	// hand-parsed fields against Windows' own decoder (TDH). Slow; tests only.
	checkLayout bool
	layoutBad   atomic.Value // first mismatch description (string)
	trackerCfg  trackerConfig
}

// Stats are running counters, safe to read while Run is going.
type Stats struct {
	Events       atomic.Uint64 // ETW events we used
	QueueDropped atomic.Uint64 // events dropped because the worker fell behind
	ETWLost      atomic.Uint64 // events Windows dropped because we read too slowly
	Flows        atomic.Uint64 // flows emitted
	LayoutChecks atomic.Uint64 // tests only: network events cross-checked with TDH
}

func (c *Collector) Name() string { return "windows-etw" }

// item is what the ETW thread hands to the worker.
type item struct {
	kind uint8 // 1 net, 2 dns, 3 process
	net  netEvent
	dns  dnsEvent
	proc procEvent
}

// Run captures until ctx is cancelled. See the collector.Collector contract.
func (c *Collector) Run(ctx context.Context, emit func(event.Flow)) error {
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	name := c.SessionName
	if name == "" {
		name = "trafficam"
	}
	qsize := c.QueueSize
	if qsize <= 0 {
		qsize = 16384
	}
	statsEvery := c.StatsEvery
	if statsEvery == 0 {
		statsEvery = 10 * time.Minute
	}

	queue := make(chan item, qsize)
	push := func(it item) {
		select {
		case queue <- it:
			c.Stats.Events.Add(1)
		default: // never make Windows wait: drop and count
			c.Stats.QueueDropped.Add(1)
		}
	}

	sess, err := startSession(name, func(rec *eventRecord) { c.onEvent(rec, push) })
	if sess == nil {
		return err
	}
	if err != nil {
		log.Warn("etw: some providers are unavailable; continuing without them", "err", err)
	}
	defer sess.Close()

	procs := newProcInfo()
	names := newDNSNames(0, 0)
	cfg := c.trackerCfg
	cfg.KeepLoopback = c.KeepLoopback
	countingEmit := func(f event.Flow) {
		c.Stats.Flows.Add(1)
		emit(f)
	}
	tr := newTracker(cfg, names, procs.lookup, countingEmit)

	handle := func(it item) {
		switch it.kind {
		case 1:
			tr.onNet(it.net)
		case 2:
			tr.onDNS(it.dns)
		case 3:
			if it.proc.Start {
				procs.started(it.proc)
			} else {
				procs.exited(it.proc.PID, it.proc.Time)
				names.forget(it.proc.PID)
			}
		}
	}

	sweep := time.NewTicker(5 * time.Second)
	defer sweep.Stop()
	var statsC <-chan time.Time
	if statsEvery > 0 {
		st := time.NewTicker(statsEvery)
		defer st.Stop()
		statsC = st.C
	}
	var reportedPanic bool
	for {
		select {
		case <-ctx.Done():
			sess.Close()
		drain: // finish what is already queued, then report open connections
			for {
				select {
				case it := <-queue:
					handle(it)
				default:
					break drain
				}
			}
			tr.flushAll()
			return nil
		case <-sess.done:
			tr.flushAll()
			return fmt.Errorf("etw: event stream ended unexpectedly: %v", sess.err)
		case it := <-queue:
			handle(it)
		case now := <-sweep.C:
			tr.sweep(now)
			names.sweep(now)
			procs.sweep(now)
			if p := callbackPanic.Load(); p != nil && !reportedPanic {
				reportedPanic = true
				log.Error("etw: recovered a panic in the event callback (capture continues)", "panic", p)
			}
		case <-statsC:
			ev, _ := sess.lost()
			c.Stats.ETWLost.Store(uint64(ev))
			log.Info("etw: stats", "events", c.Stats.Events.Load(), "flows", c.Stats.Flows.Load(),
				"queue_dropped", c.Stats.QueueDropped.Load(), "etw_lost", ev, "open_conns", len(tr.conns),
				"conn_overflow", tr.Overflow)
		}
	}
}

// onEvent runs on the ETW thread for every event. Keep it fast.
func (c *Collector) onEvent(rec *eventRecord, push func(item)) {
	h := &rec.EventHeader
	t := filetimeToTime(h.TimeStamp)
	id := h.EventDescriptor.ID
	switch h.ProviderID {
	case kernelNetworkGUID:
		ev, ok := parseKernelNetwork(id, rec.userData(), t)
		if !ok {
			return
		}
		if c.checkLayout {
			c.crossCheck(rec, ev)
		}
		push(item{kind: 1, net: ev})

	case dnsClientGUID:
		if id != dnsCompletedID {
			return
		}
		// The DNS-Client provider logs this inside the process that asked,
		// so the header's ProcessID is the asking program.
		status, _ := rec.propUint32("QueryStatus")
		push(item{kind: 2, dns: dnsEvent{
			PID:    h.ProcessID,
			Name:   cleanDNSName(rec.propString("QueryName")),
			Status: status,
			Addrs:  parseDNSResults(rec.propString("QueryResults")),
			Time:   t,
		}})

	case kernelProcessGUID:
		switch id {
		case procStartID:
			pid, _ := rec.propUint32("ProcessID")
			ppid, _ := rec.propUint32("ParentProcessID")
			push(item{kind: 3, proc: procEvent{Start: true, PID: pid, ParentPID: ppid, Image: rec.propString("ImageName"), Time: t}})
		case procStopID:
			pid, _ := rec.propUint32("ProcessID")
			push(item{kind: 3, proc: procEvent{PID: pid, Time: t}})
		}
	}
}

// crossCheck compares our hand-written parse with TDH's decode of the same
// event. Any difference means the layout in parse.go is wrong.
func (c *Collector) crossCheck(rec *eventRecord, ev netEvent) {
	c.Stats.LayoutChecks.Add(1)
	bad := func(field string, got, want any) {
		c.layoutBad.CompareAndSwap(nil, fmt.Sprintf("event %d field %s: parsed %v, TDH says %v", rec.EventHeader.EventDescriptor.ID, field, got, want))
	}
	if pid, ok := rec.propUint32("PID"); !ok || pid != ev.PID {
		bad("PID", ev.PID, pid)
	}
	if size, ok := rec.propUint32("size"); !ok || size != ev.Size {
		bad("size", ev.Size, size)
	}
	if b := rec.property("dport"); len(b) != 2 || binary.BigEndian.Uint16(b) != ev.Remote.Port() {
		bad("dport", ev.Remote.Port(), b)
	}
	if b := rec.property("sport"); len(b) != 2 || binary.BigEndian.Uint16(b) != ev.Local.Port() {
		bad("sport", ev.Local.Port(), b)
	}
	if b := rec.property("daddr"); len(b) == 0 || addrFrom(b) != ev.Remote.Addr() {
		bad("daddr", ev.Remote.Addr(), b)
	}
}
