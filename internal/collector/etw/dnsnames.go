package etw

import (
	"net/netip"
	"time"
)

// dnsNames remembers, for a while, which name each IP address came from.
//
// When chrome.exe looks up "example.org" and gets 93.184.216.34, and a moment
// later opens a connection to 93.184.216.34, we label that connection
// "example.org". Names are much more stable than IPs (CDNs rotate IPs all the
// time), so the baseline and the model work on names when they can.
//
// Two tables are kept:
//   - byPID: answers per process, the most accurate match.
//   - global: answers from any process, used as a fallback because some
//     programs connect to an address another process looked up.
//
// Not safe for concurrent use; only the worker goroutine touches it.
type dnsNames struct {
	ttl    time.Duration // how long an answer is remembered (default 15 min)
	max    int           // cap on entries per table, to bound memory
	byPID  map[uint32]map[netip.Addr]nameEntry
	global map[netip.Addr]nameEntry
	count  int // entries across all byPID maps
}

type nameEntry struct {
	name    string
	expires time.Time
}

func newDNSNames(ttl time.Duration, max int) *dnsNames {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if max <= 0 {
		max = 100_000
	}
	return &dnsNames{ttl: ttl, max: max, byPID: map[uint32]map[netip.Addr]nameEntry{}, global: map[netip.Addr]nameEntry{}}
}

// add records the answers of one successful lookup.
func (d *dnsNames) add(pid uint32, name string, addrs []netip.Addr, now time.Time) {
	if name == "" || len(addrs) == 0 {
		return
	}
	if d.count >= d.max || len(d.global) >= d.max {
		d.sweep(now)
		if d.count >= d.max || len(d.global) >= d.max { // still full: start over rather than grow
			d.byPID = map[uint32]map[netip.Addr]nameEntry{}
			d.global = map[netip.Addr]nameEntry{}
			d.count = 0
		}
	}
	e := nameEntry{name: name, expires: now.Add(d.ttl)}
	m := d.byPID[pid]
	if m == nil {
		m = map[netip.Addr]nameEntry{}
		d.byPID[pid] = m
	}
	for _, a := range addrs {
		if _, had := m[a]; !had {
			d.count++
		}
		m[a] = e
		d.global[a] = e
	}
}

// lookup returns the name pid most recently resolved to addr, or the name any
// process resolved it to, or "" if nobody did (recently).
func (d *dnsNames) lookup(pid uint32, addr netip.Addr, now time.Time) string {
	if e, ok := d.byPID[pid][addr]; ok && now.Before(e.expires) {
		return e.name
	}
	if e, ok := d.global[addr]; ok && now.Before(e.expires) {
		return e.name
	}
	return ""
}

// forget drops one process's answers (called when the process exits, so a
// new process reusing the PID does not inherit them).
func (d *dnsNames) forget(pid uint32) {
	d.count -= len(d.byPID[pid])
	delete(d.byPID, pid)
}

// sweep removes expired entries.
func (d *dnsNames) sweep(now time.Time) {
	for pid, m := range d.byPID {
		for a, e := range m {
			if !now.Before(e.expires) {
				delete(m, a)
				d.count--
			}
		}
		if len(m) == 0 {
			delete(d.byPID, pid)
		}
	}
	for a, e := range d.global {
		if !now.Before(e.expires) {
			delete(d.global, a)
		}
	}
}
