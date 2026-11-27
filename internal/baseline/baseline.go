// Package baseline keeps simple per-program counters: which destinations each
// program has talked to, since when, and on how many different days.
//
// These counters are the model-independent half of "learning what is normal".
// The rules package uses them for novelty alerts; the model has its own
// richer statistics and does not depend on this package.
package baseline

import (
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// AbsorbDays: a destination seen on this many separate days is treated as
// part of the program's normal habits (design: "repeats seen on 3 separate
// days are auto-absorbed").
const AbsorbDays = 3

// Backend is the part of store.Store the tracker needs (easy to fake in tests).
type Backend interface {
	SeenGet(keys []store.SeenKey) (map[store.SeenKey]store.Seen, error)
	SeenUpdate(rows []event.Minute) error
	ProgramSummary(prog string) (first time.Time, hosts int, err error)
	InstalledAt() (time.Time, error)
}

// Tracker reads and updates the counters.
type Tracker struct{ B Backend }

// Info describes one row's history BEFORE that row is counted.
type Info struct {
	HostKnown    bool      // this program has contacted this host before
	HostDays     int       // on how many separate days
	Absorbed     bool      // HostDays >= AbsorbDays
	ProgramFirst time.Time // zero = program never seen before
	ProgramHosts int       // distinct hosts this program has ever contacted
}

// Lookup returns one Info per row, in order. Call it before Update.
func (t *Tracker) Lookup(rows []event.Minute) ([]Info, error) {
	keys := make([]store.SeenKey, len(rows))
	for i, m := range rows {
		keys[i] = store.KeyOf(m)
	}
	seen, err := t.B.SeenGet(keys)
	if err != nil {
		return nil, err
	}
	type prog struct {
		first time.Time
		hosts int
	}
	progs := map[string]prog{}
	out := make([]Info, len(rows))
	for i, m := range rows {
		p, ok := progs[keys[i].Prog]
		if !ok {
			f, h, err := t.B.ProgramSummary(keys[i].Prog)
			if err != nil {
				return nil, err
			}
			p = prog{f, h}
			progs[keys[i].Prog] = p
		}
		s, known := seen[keys[i]]
		out[i] = Info{HostKnown: known, HostDays: s.Days, Absorbed: s.Days >= AbsorbDays,
			ProgramFirst: p.first, ProgramHosts: p.hosts}
		_ = m
	}
	return out, nil
}

// Update counts the rows. Call it after Lookup, once the batch is scored.
func (t *Tracker) Update(rows []event.Minute) error { return t.B.SeenUpdate(rows) }

// InstallAge is how long this installation has been learning.
func (t *Tracker) InstallAge(now time.Time) (time.Duration, error) {
	at, err := t.B.InstalledAt()
	return now.Sub(at), err
}
