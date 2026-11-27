package lab

import (
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// memSeen is an in-memory copy of the store's "seen" table, so a replay can
// run the real rules without a database. It must count exactly like
// store.SeenUpdate does; TestMemSeenMatchesStore checks that.
type memSeen struct {
	installed time.Time
	pairs     map[store.SeenKey]*seenRec
	progs     map[string]*progRec
}

type seenRec struct {
	s       store.Seen
	lastDay int64
}

type progRec struct {
	first time.Time
	hosts int
}

func newMemSeen(installed time.Time) *memSeen {
	return &memSeen{installed: installed, pairs: map[store.SeenKey]*seenRec{}, progs: map[string]*progRec{}}
}

func (m *memSeen) SeenGet(keys []store.SeenKey) (map[store.SeenKey]store.Seen, error) {
	out := make(map[store.SeenKey]store.Seen, len(keys))
	for _, k := range keys {
		if r, ok := m.pairs[k]; ok {
			out[k] = r.s
		}
	}
	return out, nil
}

func (m *memSeen) SeenUpdate(rows []event.Minute) error {
	for _, row := range rows {
		k := store.KeyOf(row)
		t := time.Unix(row.Start.Unix(), 0).UTC() // the store keeps whole seconds
		day := row.Start.Unix() / 86400
		r, ok := m.pairs[k]
		if !ok {
			m.pairs[k] = &seenRec{s: store.Seen{First: t, Last: t, Days: 1, Minutes: 1}, lastDay: day}
			p := m.progs[k.Prog]
			if p == nil {
				p = &progRec{first: t}
				m.progs[k.Prog] = p
			}
			p.hosts++
			if t.Before(p.first) {
				p.first = t
			}
			continue
		}
		if t.Before(r.s.First) {
			r.s.First = t
			if p := m.progs[k.Prog]; t.Before(p.first) {
				p.first = t
			}
		}
		if t.After(r.s.Last) {
			r.s.Last = t
		}
		if day > r.lastDay {
			r.s.Days++
			r.lastDay = day
		}
		r.s.Minutes++
	}
	return nil
}

func (m *memSeen) ProgramSummary(prog string) (time.Time, int, error) {
	if p, ok := m.progs[prog]; ok {
		return p.first, p.hosts, nil
	}
	return time.Time{}, 0, nil
}

func (m *memSeen) InstalledAt() (time.Time, error) { return m.installed, nil }

// memHistory is the in-memory stand-in for store.Since, used by the model's
// nightly training during a replay.
type memHistory struct{ rows []store.Scored }

func (h *memHistory) Since(t time.Time) ([]store.Scored, error) {
	// rows are appended oldest first, so binary search the start.
	lo, hi := 0, len(h.rows)
	for lo < hi {
		mid := (lo + hi) / 2
		if h.rows[mid].Minute.Start.Before(t) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return h.rows[lo:], nil
}
