package model

import (
	"math/rand/v2"
	"path/filepath"
	"testing"
	"time"
)

func TestPoisonGuardAndFeedback(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	mk := func(age time.Duration, alerted bool, fb Feedback) Sample {
		return Sample{Flow: Flow{Time: now.Add(-age)}, Alerted: alerted, Feedback: fb}
	}
	s := []Sample{
		mk(time.Hour, true, FeedbackNone),        // alerted yesterday: kept out
		mk(5*24*time.Hour, true, FeedbackNone),   // alerted 5 days ago: old enough
		mk(time.Hour, false, FeedbackNone),       // normal
		mk(time.Hour, true, FeedbackOK),          // user said OK: back in, weight 3
		mk(time.Hour, false, FeedbackLooksWrong), // never trained on
		mk(time.Hour, true, FeedbackMute),        // muted: weight 3
	}
	keep, w := eligible(s, now, 3)
	wantKeep := []int{1, 2, 3, 5}
	wantW := []float32{1, 1, 3, 3}
	if len(keep) != len(wantKeep) {
		t.Fatalf("kept %v", keep)
	}
	for i := range keep {
		if keep[i] != wantKeep[i] || w[i] != wantW[i] {
			t.Fatalf("kept %v weights %v, want %v %v", keep, w, wantKeep, wantW)
		}
	}
}

func TestPercentileInterpolation(t *testing.T) {
	a := make([]float64, 1000)
	for i := range a {
		a[i] = float64(i)
	}
	q := makeQuantiles(append([]float64(nil), a...), append([]float64(nil), a...))
	for _, c := range []struct{ v, want float64 }{{-1, 0}, {500, 50}, {990, 99}, {2000, 100}} {
		if got := interpPercentile(q.A, c.v); got < c.want-0.5 || got > c.want+0.5 {
			t.Errorf("percentile(%g) = %g, want about %g", c.v, got, c.want)
		}
	}
}

func TestAlertLineMatchesBudget(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var samples []Sample
	var scores []float64
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30000; i++ {
		samples = append(samples, Sample{Flow: Flow{Time: start.Add(time.Duration(i) * 86 * time.Second)}}) // 30 days
		scores = append(scores, r.Float64()*100)
	}
	line := alertLineFor(scores, samples, 1.5, 99)
	over := 0
	for _, s := range scores {
		if s > line {
			over++
		}
	}
	days := windowDays(samples)
	if perDay := float64(over) / days; perDay < 1.2 || perDay > 1.8 {
		t.Fatalf("line %g gives %.2f alerts/day, want about 1.5", line, perDay)
	}
}

func fixedPrior(bias float32) *HeadC {
	h := &HeadC{w1: make([]float32, 64*PriorDim), b1: make([]float32, 64), w2: make([]float32, 64*64), b2: make([]float32, 64),
		w3: make([]float32, 64), b3: []float32{bias}}
	for i := range h.Std {
		h.Std[i] = 1
	}
	return h
}

// Head C must never push a locally normal flow over the line, and never add
// more than its cap.
func TestPriorOnlyRaisesUnusualScoresWithinCap(t *testing.T) {
	sim := newSim(5)
	hist := buildHistory(sim, 10)
	cfg := DefaultNightlyConfig()
	cfg.Train.MinRecords = 1000
	cfg.Train.MaxEpochs = 1
	cfg.Train.Workers = 4
	now := simStart.AddDate(0, 0, 10)
	m, rep, err := New(2).Nightly(hist, now, cfg)
	if err != nil || !rep.Accepted {
		t.Fatalf("train: %v %+v", err, rep)
	}
	without := m.Clone()
	with := m.Clone()
	with.Prior = fixedPrior(20) // risk ~ 1 for everything
	var s Scratch
	normal := sim.day(now, 10)
	var lifted int
	for i := range normal {
		rw, rn := with.Score(&normal[i].Flow, &s), without.Score(&normal[i].Flow, &s)
		if rn.Score < m.Cfg.UnusualFloor && rw.Score != rn.Score {
			t.Fatalf("prior changed a locally normal score %g -> %g", rn.Score, rw.Score)
		}
		if rw.PriorBump > m.Cfg.PriorMax+1e-9 {
			t.Fatalf("prior added %g, cap is %g", rw.PriorBump, m.Cfg.PriorMax)
		}
		if rw.Score > rn.Score {
			lifted++
		}
	}
	t.Logf("prior lifted %d of %d locally unusual-or-above rows", lifted, len(normal))
}

func TestNightlyRejectsBadCandidate(t *testing.T) {
	sim := newSim(9)
	hist := buildHistory(sim, 12)
	now := simStart.AddDate(0, 0, 12)
	cfg := DefaultNightlyConfig()
	cfg.Train.MinRecords = 1000
	cfg.Train.MaxEpochs = 2
	cfg.Train.Workers = 4
	good, rep, err := New(3).Nightly(hist, now, cfg)
	if err != nil || !rep.Accepted {
		t.Fatalf("first model: %v %+v", err, rep)
	}
	// A bad night: program labels scrambled in the training window only.
	bad := make([]Sample, len(hist))
	copy(bad, hist)
	r := rand.New(rand.NewPCG(4, 4))
	cut := now.Add(-24 * time.Hour)
	var names []string
	for i := range bad {
		names = append(names, bad[i].Flow.Program)
	}
	for i := range bad {
		if bad[i].Flow.Time.Before(cut) {
			bad[i].Flow.Program = names[r.IntN(len(names))]
		}
	}
	cfg.Train.LR = 5e-3
	got, rep2, err := good.Nightly(bad, now.Add(time.Second), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bad night: accepted=%v reason=%q old=%.3f new=%.3f", rep2.Accepted, rep2.Reason, rep2.OldLoss, rep2.NewLoss)
	if rep2.Accepted || got != good {
		t.Fatalf("a bad night replaced the model: %+v", rep2)
	}
	// The same data unscrambled is fine.
	_, rep3, _ := good.Nightly(hist, now.Add(2*time.Second), cfg)
	if !rep3.Accepted {
		t.Fatalf("a normal night was rejected: %s", rep3.Reason)
	}
}

func TestColdStartAndSaveLoad(t *testing.T) {
	sim := newSim(1)
	hist := buildHistory(sim, 2)
	m := New(1)
	if _, err := m.Train(hist[:50], simStart.AddDate(0, 0, 2), DefaultTrainConfig()); err != ErrTooFewRecords {
		t.Fatalf("expected cold-start refusal, got %v", err)
	}
	cfg := DefaultNightlyConfig()
	cfg.Train.MinRecords = 500
	cfg.Train.MaxEpochs = 1
	now := simStart.AddDate(0, 0, 2)
	trained, rep, err := m.Nightly(hist, now, cfg)
	if err != nil || !rep.Accepted {
		t.Fatalf("%v %+v", err, rep)
	}
	p := filepath.Join(t.TempDir(), "model.tcw")
	if err := trained.Save(p); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	var s Scratch
	for i := 0; i < 50; i++ {
		f := &hist[i*7].Flow
		a, b := trained.Score(f, &s), back.Score(f, &s)
		if a.Score != b.Score || a.Alert != b.Alert {
			t.Fatalf("reloaded model disagrees: %+v vs %+v", a, b)
		}
	}
}
