package modelscore

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

type fakeHistory struct{ rows []store.Scored }

func (h *fakeHistory) Since(t time.Time) ([]store.Scored, error) {
	var out []store.Scored
	for _, r := range h.rows {
		if !r.Minute.Start.Before(t) {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestDestKey(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.com":     "example.com",
		"a.b.c.example.co.uk": "example.co.uk",
		"example.com":         "example.com",
		"93.184.216.34":       "93.184.216.0/24",
		"2001:db8:1:2::1":     "2001:db8:1::/48",
		"localhost":           "localhost",
	} {
		if got := DestKey(in); got != want {
			t.Errorf("DestKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrackerFeatures(t *testing.T) {
	tr := NewTracker()
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	row := func(min int, host string, failed uint32) event.Minute {
		return event.Minute{V: 1, Start: t0.Add(time.Duration(min) * time.Minute), Program: event.Program{Name: "app"},
			Proto: event.TCP, Dir: event.Outbound, Host: host, Port: 443, Flows: 2, BytesOut: 1000, BytesIn: 5000, FailedCount: failed}
	}
	var last model.Flow
	for i := 0; i < 5; i++ { // perfectly regular every 10 minutes
		last = tr.Observe([]event.Minute{row(i*10, "api.example.com", 0)})[0]
	}
	if !last.SeenBefore || last.Contacts1h != 5 || last.IntervalCV > 1e-9 {
		t.Fatalf("regular beacon: %+v", last)
	}
	f := tr.Observe([]event.Minute{row(60, "never-seen.example.org", 2)})[0]
	if f.SeenBefore || f.FailRate5m != 1 {
		t.Fatalf("new destination: %+v", f)
	}
	fan := tr.Observe([]event.Minute{row(70, "a.one.com", 0), row(70, "b.two.com", 0), row(70, "c.three.com", 0)})
	if fan[2].FanOut60s != 3 {
		t.Fatalf("fan-out %v", fan[2].FanOut60s)
	}
}

// A scorer fed ordinary rows for two weeks, trained, then shown an upload to a
// brand-new host from a program that never does that.
func TestScorerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("trains a model")
	}
	rng := rand.New(rand.NewPCG(3, 3))
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	progs := []struct {
		name  string
		hosts []string
		per   int
		out   float64
	}{
		{"browser", nil, 700, 3000}, {"updater", []string{"dl.vendor.com", "cdn.vendor.com"}, 40, 800},
		{"editor", []string{"ext.editor.io", "tel.editor.io"}, 80, 2000}, {"mail", []string{"imap.mail.net"}, 120, 1500},
	}
	for i := 0; i < 200; i++ {
		progs[0].hosts = append(progs[0].hosts, fmt.Sprintf("www.site%d.com", i))
	}
	hist := &fakeHistory{}
	var all []event.Minute
	for d := 0; d < 14; d++ {
		for _, p := range progs {
			for k := 0; k < p.per; k++ {
				ts := start.AddDate(0, 0, d).Add(time.Duration(rng.IntN(24*60)) * time.Minute)
				h := p.hosts[int(float64(len(p.hosts))*rng.Float64()*rng.Float64())]
				all = append(all, event.Minute{V: 1, Start: ts, Program: event.Program{Name: p.name}, Proto: event.TCP, Dir: event.Outbound,
					Host: h, Port: 443, Flows: 1, Packets: uint64(5 + rng.IntN(20)), BytesOut: uint64(p.out * (0.5 + rng.Float64())),
					BytesIn: uint64(20000 * (0.5 + rng.Float64()))})
			}
		}
	}
	// store order is by time
	sortMinutes(all)
	for _, m := range all {
		hist.rows = append(hist.rows, store.Scored{Minute: m})
	}
	now := start.AddDate(0, 0, 14)
	cfg := Config{History: hist, Now: func() time.Time { return now }}
	cfg.Nightly = model.DefaultNightlyConfig()
	cfg.Nightly.Train.MinRecords = 2000
	cfg.Nightly.Train.MaxEpochs = 2
	cfg.Nightly.Train.Workers = 4
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Untrained: silent, right count, Listening/Settling phase text present.
	v, err := s.Score(context.Background(), all[:10])
	if err != nil || len(v) != 10 || v[0].Alert || v[0].Phase == "" {
		t.Fatalf("untrained verdicts: %v %+v", err, v[0])
	}
	rep, err := s.TrainNow(context.Background())
	if err != nil || !rep.Accepted {
		t.Fatalf("train: %v %+v", err, rep)
	}
	atk := event.Minute{V: 1, Start: now.Add(2 * time.Hour), Program: event.Program{Name: "editor"}, Proto: event.TCP, Dir: event.Outbound,
		Host: "paste-drop.example.org", Port: 443, Flows: 4, Packets: 90000, BytesOut: 400_000_000, BytesIn: 3000}
	out, err := s.Score(context.Background(), []event.Minute{atk})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verdict: %+v", out[0])
	if !out[0].Alert || len(out[0].Reasons) == 0 || out[0].Score <= 0 || out[0].Score > 1 {
		t.Fatalf("exfil not flagged properly: %+v", out[0])
	}
}

func sortMinutes(m []event.Minute) { sortSlice(m) }
