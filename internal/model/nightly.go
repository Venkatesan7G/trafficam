package model

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Calibrate rebuilds the per-program score tables, the explanation scale and
// the self-set alert line from samples (normally the training window). It
// returns the final scores it computed so callers can reuse them.
func (m *Model) Calibrate(samples []Sample) []float64 {
	var s Scratch
	byClass := map[int][2][]float64{}
	var allA, allB []float64
	type pair struct{ a, b float64 }
	pairs := make([]pair, len(samples))
	var errSum [NumNum]float64
	for i := range samples {
		f := &samples[i].Flow
		a, b, in, c := m.Surprise(f, &s)
		pairs[i] = pair{a, b}
		e := s.ReconErr(&in)
		for j := range errSum {
			errSum[j] += float64(e[j])
		}
		cur := byClass[c]
		cur[0] = append(cur[0], a)
		cur[1] = append(cur[1], b)
		byClass[c] = cur
		allA = append(allA, a)
		allB = append(allB, b)
	}
	m.St.Quant = map[int]*Quantiles{}
	m.St.Quant[-1] = makeQuantiles(allA, allB)
	for c, v := range byClass {
		m.St.Quant[c] = makeQuantiles(v[0], v[1])
	}
	if len(samples) > 0 {
		for j := range errSum {
			m.St.MeanErr[j] = float32(errSum[j] / float64(len(samples)))
		}
	}
	// Final scores using the fresh tables (no alert line yet).
	m.St.AlertLine = 0
	scores := make([]float64, len(samples))
	for i := range samples {
		scores[i] = m.Score(&samples[i].Flow, &s).Score
	}
	m.St.AlertLine = alertLineFor(scores, samples, m.Cfg.AlertsPerDay, m.Cfg.DefaultLine)
	return scores
}

// alertLineFor picks the score above which the window would have produced
// about perDay alerts per day.
func alertLineFor(scores []float64, samples []Sample, perDay, fallback float64) float64 {
	if len(scores) == 0 {
		return fallback
	}
	days := windowDays(samples)
	k := int(math.Ceil(perDay * days))
	if k >= len(scores) {
		return fallback
	}
	sorted := append([]float64(nil), scores...)
	sort.Float64s(sorted)
	return sorted[len(sorted)-1-k]
}

func windowDays(samples []Sample) float64 {
	if len(samples) == 0 {
		return 1
	}
	lo, hi := samples[0].Flow.Time, samples[0].Flow.Time
	for i := range samples {
		t := samples[i].Flow.Time
		if t.Before(lo) {
			lo = t
		}
		if t.After(hi) {
			hi = t
		}
	}
	return math.Max(1, hi.Sub(lo).Hours()/24)
}

// Loss returns the mean unweighted CE+MSE of the model on samples, with no
// masking: the number nightly gating compares.
func (m *Model) Loss(samples []Sample) float64 {
	if len(samples) == 0 {
		return 0
	}
	var s Scratch
	var tot float64
	for i := range samples {
		a, b, _, _ := m.Surprise(&samples[i].Flow, &s)
		tot += a + b
	}
	return tot / float64(len(samples))
}

// NightlyConfig are the gate settings.
type NightlyConfig struct {
	Train           TrainConfig
	MaxLossRatio    float64 // candidate may be at most this x the old loss on the holdout day (1.10)
	MaxAlertBudgetX float64 // replaying the holdout day may use at most this x the daily alert budget (2)
	HoldoutHours    int
	MinHoldout      int // below this many holdout rows the gate cannot judge
}

// DefaultNightlyConfig returns the v1 gate.
func DefaultNightlyConfig() NightlyConfig {
	return NightlyConfig{Train: DefaultTrainConfig(), MaxLossRatio: 1.10, MaxAlertBudgetX: 2, HoldoutHours: 24, MinHoldout: 100}
}

// NightlyReport records what the nightly job decided and why.
type NightlyReport struct {
	Accepted     bool
	Reason       string
	Train        TrainReport
	OldLoss      float64
	NewLoss      float64
	HoldoutRows  int
	ReplayAlerts int
	ReplayLimit  float64
	AlertLine    float64
}

// Nightly trains a candidate on everything but the last 24 hours, checks it on
// that held-out day (time split, never random) and returns the model to use:
// the candidate if it passes both gates, otherwise the old model unchanged.
// The first model for a machine has nothing to be compared with and is
// accepted if it trains.
func (m *Model) Nightly(samples []Sample, now time.Time, cfg NightlyConfig) (*Model, NightlyReport, error) {
	var rep NightlyReport
	cut := now.Add(-time.Duration(cfg.HoldoutHours) * time.Hour)
	var train, hold []Sample
	for i := range samples {
		if samples[i].Flow.Time.Before(cut) {
			train = append(train, samples[i])
		} else {
			hold = append(hold, samples[i])
		}
	}
	rep.HoldoutRows = len(hold)
	cand := m.Clone()
	tr, err := cand.Train(train, now, cfg.Train)
	rep.Train = tr
	if err != nil {
		rep.Reason = "not trained: " + err.Error()
		return m, rep, nil // keeping the old model is the safe outcome, not a failure
	}
	// Tables come from the rows the candidate trained on, minus the excluded ones.
	keep, _ := eligible(train, now, cfg.Train.PoisonDays)
	kept := make([]Sample, len(keep))
	for k, i := range keep {
		kept[k] = train[i]
	}
	cand.Calibrate(kept)
	rep.AlertLine = cand.St.AlertLine

	if !m.Trained() {
		rep.Accepted, rep.Reason = true, "first model"
		return cand, rep, nil
	}
	if len(hold) < cfg.MinHoldout {
		rep.Reason = fmt.Sprintf("holdout too small to judge (%d rows); keeping old model", len(hold))
		return m, rep, nil
	}
	rep.OldLoss, rep.NewLoss = m.Loss(hold), cand.Loss(hold)
	if rep.NewLoss > rep.OldLoss*cfg.MaxLossRatio {
		rep.Reason = fmt.Sprintf("holdout loss %.4f is more than %.0f%% worse than %.4f", rep.NewLoss, (cfg.MaxLossRatio-1)*100, rep.OldLoss)
		return m, rep, nil
	}
	var s Scratch
	for i := range hold {
		if cand.Score(&hold[i].Flow, &s).Alert {
			rep.ReplayAlerts++
		}
	}
	rep.ReplayLimit = cfg.MaxAlertBudgetX * cand.Cfg.AlertsPerDay * math.Max(1, float64(cfg.HoldoutHours)/24)
	if float64(rep.ReplayAlerts) > rep.ReplayLimit {
		rep.Reason = fmt.Sprintf("replaying the holdout day would raise %d alerts (limit %.1f)", rep.ReplayAlerts, rep.ReplayLimit)
		return m, rep, nil
	}
	rep.Accepted, rep.Reason = true, "passed holdout loss and alert-budget checks"
	return cand, rep, nil
}
