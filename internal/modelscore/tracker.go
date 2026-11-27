package modelscore

import (
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/model"
)

// Tracker turns the core's per-minute rows into the model's Flow records. It
// is where "what is this program's usual behaviour" bookkeeping lives: first
// time a destination was seen, contact timing, fan-out, failure rate.
//
// Feed it rows oldest first. Training replays history through a fresh Tracker
// so training and live scoring derive features identically.
type Tracker struct {
	// UseProgramMeta feeds Program.Parent and Program.Signer to the model.
	// On by default: the store persists both (schema v2), so history replayed
	// for training carries them just like live rows.
	UseProgramMeta bool

	first    map[string]time.Time // prog|dest -> first seen
	last     map[string]time.Time // prog|dest -> last seen (for pruning)
	users    map[string]map[string]struct{}
	contacts map[string][]time.Time // prog|host -> recent minute starts (1 h)
	fails    map[string][]failRec   // prog -> last 5 minutes
	prunedAt time.Time
}

type failRec struct {
	t             time.Time
	flows, failed uint32
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{UseProgramMeta: true, first: map[string]time.Time{}, last: map[string]time.Time{}, users: map[string]map[string]struct{}{},
		contacts: map[string][]time.Time{}, fails: map[string][]failRec{}}
}

const memory = 30 * 24 * time.Hour

// Observe converts one batch of closed rows (same order out as in).
func (t *Tracker) Observe(rows []event.Minute) []model.Flow {
	// fan-out: distinct hosts per program within each minute of the batch
	type pm struct {
		prog  string
		start int64
	}
	hosts := map[pm]map[string]struct{}{}
	for i := range rows {
		k := pm{rows[i].Program.Key(), rows[i].Start.Unix()}
		if hosts[k] == nil {
			hosts[k] = map[string]struct{}{}
		}
		hosts[k][rows[i].Host] = struct{}{}
	}
	out := make([]model.Flow, len(rows))
	for i := range rows {
		m := &rows[i]
		prog := m.Program.Key()
		dest := DestKey(m.Host)
		pd := prog + "|" + dest
		first, seen := t.first[pd]
		if !seen {
			first = m.Start
			t.first[pd] = first
		}
		t.last[pd] = m.Start
		if t.users[dest] == nil {
			t.users[dest] = map[string]struct{}{}
		}
		t.users[dest][prog] = struct{}{}

		ck := prog + "|" + m.Host
		c := trim(t.contacts[ck], m.Start, time.Hour)
		c = append(c, m.Start)
		t.contacts[ck] = c

		fr := t.fails[prog]
		for len(fr) > 0 && m.Start.Sub(fr[0].t) > 5*time.Minute {
			fr = fr[1:]
		}
		fr = append(fr, failRec{m.Start, m.Flows, m.FailedCount})
		t.fails[prog] = fr
		var fl, fa uint32
		for _, r := range fr {
			fl += r.flows
			fa += r.failed
		}
		failRate := 0.0
		if fl > 0 {
			failRate = float64(fa) / float64(fl)
		}

		isIP := isIPHost(m.Host)
		f := model.Flow{
			Time:               m.Start.Local(),
			Program:            prog,
			Dest:               dest,
			ASN:                m.ASN,
			Country:            m.Country,
			Port:               m.Port,
			Proto:              model.TCP,
			Dir:                model.Outbound,
			BytesOut:           float64(m.BytesOut),
			BytesIn:            float64(m.BytesIn),
			DurationSec:        float64(m.DurationMs) / 1000,
			SendEvents:         float64(m.Packets), // GUESS: packets stand in for send events
			IntervalCV:         intervalCV(c),
			Contacts1h:         float64(len(c)),
			FanOut60s:          float64(len(hosts[pm{prog, m.Start.Unix()}])),
			FailRate5m:         failRate,
			DNSBeforeConnect:   !isIP,
			SeenBefore:         seen,
			DaysSinceFirstSeen: m.Start.Sub(first).Hours() / 24,
			OtherPrograms:      float64(len(t.users[dest]) - 1),
		}
		if m.Proto != event.TCP {
			f.Proto = model.UDP
		}
		if m.Dir == event.Inbound {
			f.Dir = model.Inbound
		}
		if !isIP {
			f.DNSEntropy, f.DNSLen = nameShape(m.Host)
		}
		if t.UseProgramMeta {
			f.Parent = m.Program.Parent
			f.Signed = m.Program.Signer != ""
		}
		out[i] = f
	}
	if len(rows) > 0 {
		t.prune(rows[len(rows)-1].Start)
	}
	return out
}

// prune forgets destinations a program has not used for 30 days. That is the
// baseline's decay: a destination unused for a month is new again.
func (t *Tracker) prune(now time.Time) {
	if now.Sub(t.prunedAt) < 24*time.Hour {
		return
	}
	t.prunedAt = now
	for k, l := range t.last {
		if now.Sub(l) > memory {
			delete(t.last, k)
			delete(t.first, k)
		}
	}
	for k, c := range t.contacts {
		if len(c) == 0 || now.Sub(c[len(c)-1]) > time.Hour {
			delete(t.contacts, k)
		}
	}
	for k, f := range t.fails {
		if len(f) == 0 || now.Sub(f[len(f)-1].t) > time.Hour {
			delete(t.fails, k)
		}
	}
	// rebuild dest -> programs from what survived
	t.users = map[string]map[string]struct{}{}
	for pd := range t.last {
		i := strings.LastIndex(pd, "|")
		prog, dest := pd[:i], pd[i+1:]
		if t.users[dest] == nil {
			t.users[dest] = map[string]struct{}{}
		}
		t.users[dest][prog] = struct{}{}
	}
}

func trim(c []time.Time, now time.Time, window time.Duration) []time.Time {
	i := 0
	for i < len(c) && now.Sub(c[i]) > window {
		i++
	}
	return c[i:]
}

// intervalCV is the coefficient of variation of gaps between contacts; 0 when
// there are fewer than 3 contacts (not enough to call regular or irregular).
func intervalCV(c []time.Time) float64 {
	if len(c) < 3 {
		return 0
	}
	var gaps []float64
	for i := 1; i < len(c); i++ {
		gaps = append(gaps, c[i].Sub(c[i-1]).Seconds())
	}
	var mean float64
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	if mean == 0 {
		return 0
	}
	var v float64
	for _, g := range gaps {
		v += (g - mean) * (g - mean)
	}
	return math.Sqrt(v/float64(len(gaps))) / mean
}

func isIPHost(h string) bool {
	_, err := netip.ParseAddr(h)
	return err == nil
}

// twoPart lists common public suffixes with two labels. GUESS: a real build
// should embed the Public Suffix List; this keeps v1 dependency-free.
var twoPart = map[string]bool{"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "com.au": true, "net.au": true,
	"co.jp": true, "co.in": true, "com.br": true, "com.cn": true, "co.nz": true, "co.za": true, "com.mx": true}

// DestKey names a destination the way the model keys it: the registrable
// domain for DNS names (stable across CDN IP churn), the /24 (or /48) for IP
// addresses (GUESS: groups a provider's rotating addresses).
func DestKey(host string) string {
	if a, err := netip.ParseAddr(host); err == nil {
		bits := 24
		if a.Is6() {
			bits = 48
		}
		p, _ := a.Prefix(bits)
		return p.String()
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	n := 2
	if twoPart[strings.Join(parts[len(parts)-2:], ".")] {
		n = 3
	}
	if len(parts) < n {
		n = len(parts)
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

// nameShape returns the Shannon entropy of the registrable domain's main label
// and the full name length: generated domains score high on both.
func nameShape(host string) (entropy, length float64) {
	key := DestKey(host)
	label := key
	if i := strings.Index(key, "."); i > 0 {
		label = key[:i]
	}
	counts := map[rune]int{}
	for _, r := range label {
		counts[r]++
	}
	n := float64(len(label))
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy, float64(len(host))
}
