package lab

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Synthetic makes a fake but plausible multi-day recording of one PC, in
// minute rows. It exists so the lab can be tested and demonstrated without
// anyone's real traffic. Numbers measured on it say the tools work, NOT how
// trafficam behaves on a real machine.
//
// The machine has a browser with a long tail of sites (it keeps finding new
// ones), a few chatty background programs with fixed destinations, a time
// sync service, and one ordinary program installed half-way through (a benign
// "new program", which the rules will flag).
func Synthetic(start time.Time, days int, seed uint64) *Data {
	rng := rand.New(rand.NewPCG(seed, 99))
	type prog struct {
		p       event.Program
		hosts   []string
		every   time.Duration // one row per host-pick at this interval
		dayOnly bool          // only 08:00-22:00 UTC
		port    uint16
		proto   event.Proto
		outMu   float64
		inMu    float64
		fromDay int
	}
	sites := make([]string, 600)
	for i := range sites {
		sites[i] = fmt.Sprintf("www.site%03d.test", i) // separate domains, like real sites
	}
	progs := []prog{
		{event.Program{Name: "firefox", Path: "/usr/lib/firefox/firefox", Parent: "gnome-shell", Signer: "deb:firefox"}, sites, 25 * time.Second, true, 443, event.TCP, 7, 10, 0},
		{event.Program{Name: "updater", Path: "/usr/bin/updater", Parent: "systemd", Signer: "deb:updater"}, []string{"updates.vendor.example", "cdn.vendor.example"}, 30 * time.Minute, false, 443, event.TCP, 6, 9, 0},
		{event.Program{Name: "mail", Path: "/usr/bin/mail-client", Parent: "gnome-shell", Signer: "deb:mail"}, []string{"imap.mail.example", "smtp.mail.example"}, 5 * time.Minute, true, 993, event.TCP, 6, 8, 0},
		{event.Program{Name: "chat", Path: "/opt/chat/chat", Parent: "gnome-shell"}, []string{"gw.chat.example", "media.chat.example", "cdn.chat.example"}, 3 * time.Minute, true, 443, event.TCP, 6, 8, 0},
		{event.Program{Name: "chronyd", Path: "/usr/sbin/chronyd", Parent: "systemd", Signer: "deb:chrony", Service: "chrony.service"}, []string{"ntp.example.org"}, time.Hour, false, 123, event.UDP, 4, 4, 0},
		{event.Program{Name: "editor", Path: "/usr/bin/editor", Parent: "gnome-shell", Signer: "deb:editor"}, []string{"extensions.editor.example", "telemetry.editor.example"}, 20 * time.Minute, true, 443, event.TCP, 6, 8, days / 2},
	}
	d := &Data{Source: fmt.Sprintf("synthetic (%d days, seed %d)", days, seed), Installed: start}
	for di := 0; di < days; di++ {
		day := start.AddDate(0, 0, di)
		var rows []event.Minute
		for _, p := range progs {
			if di < p.fromDay {
				continue
			}
			for t := day.Add(time.Duration(rng.IntN(int(p.every/time.Second))) * time.Second); t.Before(day.Add(24 * time.Hour)); t = t.Add(jitter(rng, p.every)) {
				if p.dayOnly && (t.Hour() < 8 || t.Hour() >= 22) {
					continue
				}
				h := p.hosts[pick(rng, len(p.hosts), p.p.Name == "firefox")]
				flows := uint32(1 + rng.IntN(4))
				rows = append(rows, event.Minute{
					V: event.SchemaVersion, Start: t.UTC().Truncate(time.Minute), Program: p.p, Proto: p.proto, Dir: event.Outbound,
					Host: h, RemoteIP: fakeIP(h), Port: p.port, Flows: flows, Packets: uint64(flows) * uint64(4+rng.IntN(20)),
					BytesOut: uint64(math.Exp(p.outMu + rng.NormFloat64()*0.6)), BytesIn: uint64(math.Exp(p.inMu + rng.NormFloat64()*0.8)),
					ASN: 64500 + uint32(len(h)%7), Country: "DE", DurationMs: uint64(500 + rng.IntN(5000)),
				})
			}
		}
		SortRows(rows)
		d.Rows = append(d.Rows, mergeSame(rows)...)
	}
	return d
}

// mergeSame folds rows with the same minute and key into one, as the live
// aggregator would.
func mergeSame(rows []event.Minute) []event.Minute {
	type k struct {
		t          string
		prog, host string
		port       uint16
		proto      event.Proto
		dir        event.Direction
	}
	idx := map[k]int{}
	var out []event.Minute
	for _, r := range rows {
		key := k{r.Start.String(), r.Program.Key(), r.Host, r.Port, r.Proto, r.Dir}
		if i, ok := idx[key]; ok {
			o := &out[i]
			o.Flows += r.Flows
			o.Packets += r.Packets
			o.BytesIn += r.BytesIn
			o.BytesOut += r.BytesOut
			o.DurationMs += r.DurationMs
			o.FailedCount += r.FailedCount
			continue
		}
		idx[key] = len(out)
		out = append(out, r)
	}
	return out
}

func jitter(rng *rand.Rand, every time.Duration) time.Duration {
	f := 0.5 + rng.Float64()
	return time.Duration(float64(every) * f)
}

// pick returns an index; long-tailed (Zipf-like) for the browser.
func pick(rng *rand.Rand, n int, tail bool) int {
	if !tail {
		return rng.IntN(n)
	}
	i := int(math.Exp(rng.Float64()*math.Log(float64(n)))) - 1
	return min(max(i, 0), n-1)
}

func fakeIP(host string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(host); i++ {
		h = (h ^ uint32(host[i])) * 16777619
	}
	return fmt.Sprintf("198.51.%d.%d", (h>>8)%256, h%254+1)
}
