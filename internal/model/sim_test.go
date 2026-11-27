package model

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
	"time"
)

// A synthetic machine, good enough to exercise training, calibration, gating
// and detection end to end. It is NOT evidence of real-world accuracy: the
// real measurements need volunteer traffic (see docs/model.md).

type simProg struct {
	name, parent string
	signed       bool
	dests        []string
	zipf         float64 // 0 = uniform over dests
	perDay       int
	outMu, inMu  float64 // log-normal means of bytes
	periodic     bool
	asn          uint32
	port         uint16
}

func simProgs() []simProg {
	web := make([]string, 400)
	for i := range web {
		web[i] = fmt.Sprintf("site%03d.example.com", i)
	}
	return []simProg{
		{"firefox", "explorer", true, web, 1.1, 1500, 7, 10, false, 15169, 443},
		{"updater", "systemd", true, []string{"updates.vendor.com", "cdn.vendor.com"}, 0, 60, 5, 9, true, 13335, 443},
		{"mailclient", "explorer", true, []string{"imap.mail.com", "smtp.mail.com"}, 0, 120, 6, 8, true, 8075, 993},
		{"winword", "explorer", true, []string{"office365.example.net"}, 0, 40, 6, 7, false, 8075, 443},
		{"editor", "explorer", true, []string{"extensions.editor.io", "telemetry.editor.io"}, 0, 70, 6, 8, false, 14618, 443},
		{"syncclient", "systemd", true, []string{"api.sync.example", "blob.sync.example"}, 0, 200, 9, 9, true, 16509, 443},
		{"chatapp", "explorer", true, []string{"gateway.chat.example", "media.chat.example", "cdn.chat.example"}, 0, 300, 6, 8, true, 14618, 443},
	}
}

type simMachine struct {
	rng  *rand.Rand
	prog []simProg
	seen map[string]float64 // program|dest -> first-seen day
}

func newSim(seed uint64) *simMachine {
	return &simMachine{rng: rand.New(rand.NewPCG(seed, 5)), prog: simProgs(), seen: map[string]float64{}}
}

func (s *simMachine) pick(p *simProg) string {
	if p.zipf == 0 {
		return p.dests[s.rng.IntN(len(p.dests))]
	}
	u := s.rng.Float64()
	i := int(math.Pow(u, 1/(1-0.0)) * math.Pow(float64(len(p.dests)), u))
	if i >= len(p.dests) {
		i = len(p.dests) - 1
	}
	return p.dests[i%len(p.dests)]
}

func (s *simMachine) day(start time.Time, dayIdx int) []Sample {
	var out []Sample
	for pi := range s.prog {
		p := &s.prog[pi]
		n := p.perDay/2 + s.rng.IntN(p.perDay)
		for k := 0; k < n; k++ {
			h := 8 + s.rng.NormFloat64()*4 + 6
			if p.periodic {
				h = s.rng.Float64() * 24
			}
			h = math.Mod(math.Mod(h, 24)+24, 24)
			t := start.Add(time.Duration(h*3600) * time.Second)
			d := s.pick(p)
			key := p.name + "|" + d
			seen := false
			if _, ok := s.seen[key]; ok {
				seen = true
			} else {
				s.seen[key] = float64(dayIdx)
			}
			cv := 0.8 + s.rng.Float64()*0.6
			if p.periodic {
				cv = 0.05 + s.rng.Float64()*0.1
			}
			f := Flow{
				Time: t, Program: p.name, Dest: d, ASN: p.asn, Parent: p.parent, Country: "US", Port: p.port,
				BytesOut: math.Exp(p.outMu + s.rng.NormFloat64()*0.6), BytesIn: math.Exp(p.inMu + s.rng.NormFloat64()*0.7),
				DurationSec: math.Exp(1 + s.rng.NormFloat64()*0.5), SendEvents: float64(1 + s.rng.IntN(8)),
				IntervalCV: cv, Contacts1h: float64(1 + s.rng.IntN(6)), FanOut60s: float64(1 + s.rng.IntN(3)),
				FailRate5m: s.rng.Float64() * 0.03, DNSBeforeConnect: true, DNSEntropy: 2.8 + s.rng.Float64()*0.6,
				DNSLen: float64(len(d)), SeenBefore: seen, DaysSinceFirstSeen: float64(dayIdx) - s.seen[key],
				OtherPrograms: 0, Signed: p.signed,
			}
			out = append(out, Sample{Flow: f})
		}
	}
	return out
}

type attack struct {
	name string
	f    Flow
}

func (s *simMachine) attacks(at time.Time) []attack {
	base := func(prog, dest string, t time.Time) Flow {
		return Flow{Time: t, Program: prog, Dest: dest, ASN: 99999, Parent: "explorer", Country: "RU", Port: 443,
			BytesOut: 400, BytesIn: 300, DurationSec: 1, SendEvents: 2, IntervalCV: 0.02, Contacts1h: 12, FanOut60s: 1,
			DNSBeforeConnect: true, DNSEntropy: 3.1, DNSLen: 20, Signed: true}
	}
	var a []attack
	for i := 0; i < 5; i++ { // beacon from a program that normally talks to one host
		f := base("winword", "evil-update.example.org", at.Add(time.Duration(i)*time.Hour))
		f.Parent = "cmd"
		a = append(a, attack{"beacon", f})
	}
	for i := 0; i < 5; i++ { // exfiltration: huge upload to a new destination
		f := base("editor", "paste-drop.example.org", at.Add(time.Duration(i)*time.Hour+10*time.Minute))
		f.BytesOut, f.BytesIn, f.DurationSec, f.SendEvents = 8e7, 2e3, 240, 5000
		a = append(a, attack{"exfil", f})
	}
	for i := 0; i < 5; i++ { // DGA: random-looking names, many failures
		f := base("chatapp", fmt.Sprintf("x%dq%dkz%d.biz", i*7919, i*104729, i), at.Add(time.Duration(i)*time.Hour+20*time.Minute))
		f.DNSEntropy, f.DNSLen, f.FailRate5m, f.FanOut60s = 4.4, 28, 0.8, 30
		a = append(a, attack{"dga", f})
	}
	for i := 0; i < 5; i++ { // hard case: normal-looking traffic to a brand-new site
		f := base("firefox", fmt.Sprintf("newsite%d.example.com", i), at.Add(time.Duration(i)*time.Hour+40*time.Minute))
		f.ASN, f.Country, f.BytesOut, f.BytesIn, f.IntervalCV, f.Contacts1h, f.DNSEntropy = 15169, "US", 1100, 22000, 1.0, 2, 3.0
		a = append(a, attack{"newsite", f})
	}
	for i := 0; i < 5; i++ { // scan from a normal program
		f := base("mailclient", fmt.Sprintf("10.0.0.%d", i+1), at.Add(time.Duration(i)*time.Hour+30*time.Minute))
		f.Port, f.FanOut60s, f.FailRate5m, f.BytesOut, f.BytesIn, f.ASN = 22+uint16(i), 250, 0.95, 60, 0, 0
		a = append(a, attack{"scan", f})
	}
	return a
}

var simStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func buildHistory(s *simMachine, days int) []Sample {
	var all []Sample
	for d := 0; d < days; d++ {
		all = append(all, s.day(simStart.AddDate(0, 0, d), d)...)
	}
	return all
}

func fastNightly() NightlyConfig {
	c := DefaultNightlyConfig()
	c.Train.MaxEpochs = 3
	c.Train.Workers = 4
	return c
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("trains a model; skipped with -short")
	}
	sim := newSim(42)
	hist := buildHistory(sim, 30)
	now := simStart.AddDate(0, 0, 30)
	t0 := time.Now()
	m, rep, err := New(1).Nightly(hist, now, fastNightly())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("trained %d rows in %v: %+v", len(hist), time.Since(t0).Round(time.Millisecond), rep)
	if !rep.Accepted {
		t.Fatalf("first model rejected: %s", rep.Reason)
	}

	// Day 31: normal traffic plus planted attacks. Benign rows must not trip the line.
	day := sim.day(now, 30)
	var sc Scratch
	var benignAlerts int
	for i := range day {
		if m.Score(&day[i].Flow, &sc).Alert {
			benignAlerts++
		}
	}
	caught := map[string]int{}
	total := map[string]int{}
	var example Result
	var exFlow Flow
	for _, a := range sim.attacks(now.Add(2 * time.Hour)) {
		total[a.name]++
		r := m.Score(&a.f, &sc)
		if r.Alert {
			caught[a.name]++
			if a.name == "exfil" {
				example, exFlow = r, a.f
			}
		}
	}
	t.Logf("benign alerts on a fresh day (%d flows): %d; alert line %.2f", len(day), benignAlerts, m.St.AlertLine)
	var c, n int
	for k, v := range total {
		t.Logf("  %-7s caught %d/%d", k, caught[k], v)
		if k == "newsite" { // a new site with normal features is the known hard case; reported, not gated
			continue
		}
		c += caught[k]
		n += v
	}
	if benignAlerts > 6 {
		t.Errorf("too noisy: %d alerts on a normal day (budget ~1.5)", benignAlerts)
	}
	if float64(c)/float64(n) < 0.8 {
		t.Errorf("caught %d/%d planted attacks, want at least 80%%", c, n)
	}
	for _, r := range m.Explain(&exFlow, example, 3) {
		t.Logf("  reason %.0f%% %s: %s", r.Share*100, r.Feature, r.Text)
	}
}
