package lab

import (
	"encoding/base32"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Planted attacks. Each one is written as the minute rows trafficam would
// record if the attack really ran on that PC, and is mixed into a clean
// recording ("injection"). The rows carry a label so the lab knows which
// alerts were hits and which were false alarms.
//
// The shapes are modelled on what the public reports describe (C2 beacons,
// staged exfiltration, domain generation, DNS tunnelling, scans), but they
// are still our own guesses at those shapes: the VM scripts in lab/vm make
// the real traffic for the same scenarios.

// Attack describes one planted scenario.
type Attack struct {
	ID       string // e.g. "beacon-quiet"
	Kind     string // beacon, exfil, dga, dns-tunnel, scan, new-program
	What     string // one line for the report
	Hard     bool   // expected to be hard for the rules (the model's job)
	Start    time.Time
	Rows     int
	Program  string // program key the attack runs as
	Hijacked bool   // runs inside an existing program (vs a new one)
}

// Labels marks rows of a Data: Labels[i] is the attack ID of row i, "" = clean.
type Labels []string

// attackCtx picks the programs the attacks pretend to hijack.
type attackCtx struct {
	quiet []quietProg   // settled, few destinations, busy enough (e.g. an updater), most rows first
	busy  event.Program // most destinations (e.g. the browser)
}

type quietProg struct {
	p     event.Program
	known string // a destination it already uses most (for exfil to a known host)
	port  uint16
}

func pickPrograms(d *Data, before time.Time, minAge time.Duration) (attackCtx, error) {
	type st struct {
		p     event.Program
		hosts map[string]int
		first time.Time
		rows  int
	}
	progs := map[string]*st{}
	for _, m := range d.Rows {
		if !m.Start.Before(before) {
			break
		}
		if m.Proto == event.DNS || m.Host == "" {
			continue
		}
		s := progs[m.Program.Key()]
		if s == nil {
			s = &st{p: m.Program, hosts: map[string]int{}, first: m.Start}
			progs[m.Program.Key()] = s
		}
		s.hosts[m.Host]++
		s.rows++
	}
	var all []*st
	for _, s := range progs {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].p.Key() < all[j].p.Key() })
	var c attackCtx
	var quiet []*st
	var busy *st
	for _, s := range all {
		settled := before.Sub(s.first) >= minAge
		if settled && len(s.hosts) <= 5 && s.rows >= 50 {
			quiet = append(quiet, s)
		}
		if busy == nil || len(s.hosts) > len(busy.hosts) {
			busy = s
		}
	}
	if len(quiet) == 0 || busy == nil {
		return c, fmt.Errorf("lab: the recording needs a settled program with at most 5 destinations and some traffic before %s to plant attacks into", before.Format("2006-01-02"))
	}
	sort.SliceStable(quiet, func(i, j int) bool { return quiet[i].rows > quiet[j].rows })
	c.busy = busy.p
	for _, q := range quiet {
		qp := quietProg{p: q.p}
		best := 0
		for h, n := range q.hosts {
			if n > best || (n == best && h < qp.known) {
				qp.known, best = h, n
			}
		}
		for _, m := range d.Rows {
			if m.Program.Key() == q.p.Key() && m.Host == qp.known {
				qp.port = m.Port
				break
			}
		}
		c.quiet = append(c.quiet, qp)
	}
	return c, nil
}

// InjectOptions control injection.
type InjectOptions struct {
	At   time.Time // when the first attack starts; zero = 75% through the recording
	Seed uint64
	Only []string // attack IDs to plant; empty = all
	// MinHistory is how long the install must have run before the attacks,
	// and how old a program must be to count as quiet [4 days]. Tuning uses
	// a shorter one to plant an "early" wave right after install.
	MinHistory time.Duration
	IDSuffix   string        // appended to every attack ID (to plant several waves)
	Prev       Labels        // labels of d's rows from an earlier wave, kept
	Gap        time.Duration // time between attacks [7h]
}

// Inject plants every attack scenario into a copy of d, one every 7 hours
// from opt.At, and returns the new data, its labels and the attack list.
func Inject(d *Data, opt InjectOptions) (*Data, Labels, []Attack, error) {
	if len(d.Rows) == 0 {
		return nil, nil, nil, fmt.Errorf("lab: nothing to plant attacks into")
	}
	first, last := d.Rows[0].Start, d.Rows[len(d.Rows)-1].Start
	at := opt.At
	if at.IsZero() {
		at = first.Add(last.Sub(first) * 3 / 4).Truncate(time.Hour)
	}
	if opt.MinHistory <= 0 {
		opt.MinHistory = 4 * 24 * time.Hour
	}
	if opt.Gap <= 0 {
		opt.Gap = 7 * time.Hour
	}
	if at.Sub(d.InstallTime()) < opt.MinHistory {
		return nil, nil, nil, fmt.Errorf("lab: attacks start %s, under %s after the install; record longer (at least 6 days, ideally 14+)", at.Format("2006-01-02 15:04"), opt.MinHistory)
	}
	c, err := pickPrograms(d, at, opt.MinHistory)
	if err != nil {
		return nil, nil, nil, err
	}
	rng := rand.New(rand.NewPCG(opt.Seed, 7))
	// Attacks that run inside a quiet program take turns over the quiet
	// programs, so one attack's burst of new destinations does not change
	// how the next attack looks (a program that has suddenly contacted 300
	// names is no longer "quiet"). With only one quiet program they share it,
	// and the report shows the effect.
	nq := 0
	// Each wave uses its own server names, or a later wave's "new" server
	// would already be known from the earlier one.
	tag := ""
	if opt.IDSuffix != "" {
		tag = "w" + strings.Trim(strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			return '-'
		}, strings.ToLower(opt.IDSuffix)), "-") + "-"
	}
	q := func() quietProg { p := c.quiet[nq%len(c.quiet)]; nq++; return p }
	type gen struct {
		a Attack
		f func(a *Attack) []event.Minute
	}
	gens := []gen{
		{Attack{ID: "beacon-quiet", Kind: "beacon", What: "the quiet program calls a new server every ~5 min for 6 h with tiny requests", Hijacked: true},
			func(a *Attack) []event.Minute {
				return beacon(rng, a.Start, q().p, tag+"cdn-sync-check.example.net", 443, 6*time.Hour, 5*time.Minute)
			}},
		{Attack{ID: "beacon-browser", Kind: "beacon", What: "the browser calls a new site every ~2 min for 6 h with tiny requests", Hard: true, Hijacked: true},
			func(a *Attack) []event.Minute {
				return beacon(rng, a.Start, c.busy, tag+"static-assets-cache.example.org", 443, 6*time.Hour, 2*time.Minute)
			}},
		{Attack{ID: "exfil-new", Kind: "exfil", What: "the quiet program uploads ~600 MB to a new server over 30 min", Hijacked: true},
			func(a *Attack) []event.Minute {
				return exfil(rng, a.Start, q().p, tag+"files-drop.example.net", 443, 30, 20e6)
			}},
		{Attack{ID: "exfil-known", Kind: "exfil", What: "the quiet program uploads ~600 MB to a server it already uses (abused cloud account)", Hard: true, Hijacked: true},
			func(a *Attack) []event.Minute {
				qp := q()
				return exfil(rng, a.Start, qp.p, qp.known, qp.port, 30, 20e6)
			}},
		{Attack{ID: "exfil-browser", Kind: "exfil", What: "the browser uploads ~600 MB to a new site over 30 min", Hard: true, Hijacked: true},
			func(a *Attack) []event.Minute {
				return exfil(rng, a.Start, c.busy, tag+"upload-share.example.org", 443, 30, 20e6)
			}},
		{Attack{ID: "dga", Kind: "dga", What: "the quiet program looks up 300 random-looking names (most fail), then connects to one", Hijacked: true},
			func(a *Attack) []event.Minute { return dga(rng, a.Start, q().p) }},
		{Attack{ID: "dns-tunnel", Kind: "dns-tunnel", What: "the quiet program sends data out as 2,000 long DNS names under one domain", Hijacked: true},
			func(a *Attack) []event.Minute { return dnsTunnel(rng, a.Start, q().p, tag+"t.example.net") }},
		{Attack{ID: "scan", Kind: "scan", What: "the quiet program tries 250 LAN addresses on SMB/SSH/RDP, nearly all refused", Hijacked: true},
			func(a *Attack) []event.Minute { return scan(rng, a.Start, q().p) }},
		{Attack{ID: "dropper", Kind: "new-program", What: "a never-seen program in a temp folder beacons to a new server"},
			func(a *Attack) []event.Minute {
				p := event.Program{Name: "svchelper", Path: "/tmp/.cache/" + tag + "svchelper", Parent: c.busy.Name}
				return beacon(rng, a.Start, p, tag+"update-check.example.com", 8443, 3*time.Hour, 3*time.Minute)
			}},
	}
	out := &Data{Rows: append([]event.Minute(nil), d.Rows...), Installed: d.Installed, Source: d.Source + " + planted attacks"}
	labels := make([]string, len(out.Rows))
	copy(labels, opt.Prev)
	var attacks []Attack
	t := at
	for _, g := range gens {
		if len(opt.Only) > 0 && !contains(opt.Only, g.a.ID) {
			continue
		}
		a := g.a
		a.ID += opt.IDSuffix
		a.Start = t
		rows := g.f(&a)
		a.Rows = len(rows)
		a.Program = rows[0].Program.Key()
		attacks = append(attacks, a)
		for range rows {
			labels = append(labels, a.ID)
		}
		out.Rows = append(out.Rows, rows...)
		t = t.Add(opt.Gap)
	}
	// Sort rows and labels together.
	idx := make([]int, len(out.Rows))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool { return out.Rows[idx[i]].Start.Before(out.Rows[idx[j]].Start) })
	rows := make([]event.Minute, len(idx))
	lab := make(Labels, len(idx))
	for k, i := range idx {
		rows[k], lab[k] = out.Rows[i], labels[i]
	}
	out.Rows = rows
	return out, lab, attacks, nil
}

func row(p event.Program, t time.Time, proto event.Proto, host, ip string, port uint16) event.Minute {
	return event.Minute{V: event.SchemaVersion, Start: t.UTC().Truncate(time.Minute), Program: p, Proto: proto,
		Dir: event.Outbound, Host: host, RemoteIP: ip, Port: port, Flows: 1, Packets: 6}
}

func beacon(rng *rand.Rand, start time.Time, p event.Program, host string, port uint16, dur, every time.Duration) []event.Minute {
	var out []event.Minute
	for t := start; t.Before(start.Add(dur)); t = t.Add(every + time.Duration(rng.IntN(20))*time.Second) {
		m := row(p, t, event.TCP, host, "203.0.113.50", port)
		m.BytesOut, m.BytesIn, m.DurationMs = uint64(300+rng.IntN(200)), uint64(200+rng.IntN(300)), uint64(200+rng.IntN(300))
		out = append(out, m)
	}
	return out
}

func exfil(rng *rand.Rand, start time.Time, p event.Program, host string, port uint16, minutes int, perMin float64) []event.Minute {
	var out []event.Minute
	for i := 0; i < minutes; i++ {
		m := row(p, start.Add(time.Duration(i)*time.Minute), event.TCP, host, "203.0.113.60", port)
		m.BytesOut = uint64(perMin * (0.8 + 0.4*rng.Float64()))
		m.BytesIn, m.Packets, m.DurationMs, m.Flows = uint64(20000+rng.IntN(5000)), 15000, 60000, 2
		out = append(out, m)
	}
	return out
}

func randLabel(rng *rand.Rand, n int) string {
	const a = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[rng.IntN(len(a))]
	}
	return string(b)
}

func dga(rng *rand.Rand, start time.Time, p event.Program) []event.Minute {
	var out []event.Minute
	tlds := []string{"com", "net", "biz", "info", "org"}
	var winner string
	for i := 0; i < 300; i++ {
		name := randLabel(rng, 12+rng.IntN(10)) + "." + tlds[rng.IntN(len(tlds))]
		t := start.Add(time.Duration(i*2) * time.Second)
		m := row(p, t, event.DNS, name, "", 53)
		m.BytesOut, m.BytesIn = 40, 100
		out = append(out, m)
		if i == 287 {
			winner = name
		}
	}
	m := row(p, start.Add(10*time.Minute), event.TCP, winner, "203.0.113.70", 443)
	m.BytesOut, m.BytesIn = 800, 4000
	out = append(out, m)
	for i := 0; i < 20; i++ { // failed connection attempts to other generated names' addresses
		f := row(p, start.Add(time.Duration(i)*20*time.Second), event.TCP, fmt.Sprintf("203.0.113.%d", 100+i), "", 443)
		f.FailedCount, f.Packets = 1, 2
		out = append(out, f)
	}
	return out
}

func dnsTunnel(rng *rand.Rand, start time.Time, p event.Program, domain string) []event.Minute {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	var out []event.Minute
	for i := 0; i < 2000; i++ {
		buf := make([]byte, 30)
		for k := range buf {
			buf[k] = byte(rng.IntN(256))
		}
		name := strings.ToLower(enc.EncodeToString(buf)) + "." + domain
		m := row(p, start.Add(time.Duration(i)*900*time.Millisecond), event.DNS, name, "", 53)
		m.BytesOut, m.BytesIn = 110, 130
		out = append(out, m)
	}
	return out
}

func scan(rng *rand.Rand, start time.Time, p event.Program) []event.Minute {
	var out []event.Minute
	ports := []uint16{445, 22, 3389}
	for i := 0; i < 250; i++ {
		ip := fmt.Sprintf("192.168.1.%d", 1+i)
		m := row(p, start.Add(time.Duration(i)*time.Second), event.TCP, ip, ip, ports[i%3])
		m.Packets, m.FailedCount = 2, 1
		if rng.IntN(50) == 0 { // a few hosts answer
			m.FailedCount, m.BytesIn, m.BytesOut = 0, 120, 80
		}
		out = append(out, m)
	}
	return out
}
