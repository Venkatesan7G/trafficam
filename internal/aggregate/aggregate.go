// Package aggregate rolls raw Flows up into per-minute Minute records.
//
// Rows are keyed by (minute, program, protocol, direction, host, port), so a
// browser opening 500 connections to the same CDN in a minute becomes one row
// with Flows=500. This keeps the database small and makes the model's inputs
// independent of how chatty a connection is.
package aggregate

import (
	"sort"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

type key struct {
	start time.Time
	prog  string
	proto event.Proto
	dir   event.Direction
	host  string
	port  uint16
}

// Aggregator is NOT safe for concurrent use; the service owns it from one goroutine.
type Aggregator struct {
	rows    map[key]*event.Minute
	maxSeen time.Time // newest event time seen so far
}

func New() *Aggregator { return &Aggregator{rows: map[key]*event.Minute{}} }

// Add merges one flow into its minute bucket.
func (a *Aggregator) Add(f event.Flow) {
	start := f.Time.UTC().Truncate(time.Minute)
	if f.Time.After(a.maxSeen) {
		a.maxSeen = f.Time
	}
	k := key{start, f.Program.Key(), f.Proto, f.Dir, f.Host(), f.Remote.Port()}
	m, ok := a.rows[k]
	if !ok {
		m = &event.Minute{
			V: event.SchemaVersion, Start: start, Program: f.Program,
			Proto: f.Proto, Dir: f.Dir, Host: k.host, Port: k.port,
		}
		a.rows[k] = m
	}
	m.Flows++
	m.Packets += f.Packets
	m.BytesIn += f.BytesIn
	m.BytesOut += f.BytesOut
	if f.Remote.Addr().IsValid() {
		m.RemoteIP = f.Remote.Addr().String()
	}
	if f.Proto == event.TCP && !f.Established {
		m.FailedCount++
	}
}

// CloseOld removes and returns every row whose minute is entirely before cutoff,
// oldest first. Use CloseLate in replay/offline mode, or call with
// time.Now().Add(-grace) on a ticker in live mode.
func (a *Aggregator) CloseOld(cutoff time.Time) []event.Minute {
	var out []event.Minute
	for k, m := range a.rows {
		if m.Start.Add(time.Minute).Before(cutoff) || m.Start.Add(time.Minute).Equal(cutoff) {
			out = append(out, *m)
			delete(a.rows, k)
		}
	}
	sortMinutes(out)
	return out
}

// CloseByEventTime closes minutes that are more than `grace` older than the
// newest event seen. This makes closing deterministic during replay, where
// wall-clock time is meaningless.
func (a *Aggregator) CloseByEventTime(grace time.Duration) []event.Minute {
	if a.maxSeen.IsZero() {
		return nil
	}
	return a.CloseOld(a.maxSeen.Add(-grace))
}

// Drain returns everything still open (used on shutdown).
func (a *Aggregator) Drain() []event.Minute {
	out := make([]event.Minute, 0, len(a.rows))
	for k, m := range a.rows {
		out = append(out, *m)
		delete(a.rows, k)
	}
	sortMinutes(out)
	return out
}

func sortMinutes(m []event.Minute) {
	sort.Slice(m, func(i, j int) bool {
		if !m[i].Start.Equal(m[j].Start) {
			return m[i].Start.Before(m[j].Start)
		}
		if m[i].Program.Key() != m[j].Program.Key() {
			return m[i].Program.Key() < m[j].Program.Key()
		}
		return m[i].Host < m[j].Host
	})
}
