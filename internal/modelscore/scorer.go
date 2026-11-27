// Package modelscore plugs the model into the core: it implements
// score.Scorer, derives the model's features from per-minute rows, and runs
// the nightly training job against the stored history.
package modelscore

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// History is the part of the store the scorer reads for training.
type History interface {
	Since(time.Time) ([]store.Scored, error)
}

// Config configures the scorer.
type Config struct {
	ModelPath string // where the trained model is saved and loaded; "" = memory only
	History   History
	Prior     *model.HeadC // frozen head C, nil when the user switch is off
	Nightly   model.NightlyConfig
	Explain   int // reasons per alert (default 3)
	Log       *slog.Logger
	Now       func() time.Time
	Idle      func() bool // true when training may run (idle and on AC); nil = always
	RunHour   int         // local hour for the nightly job (default 3)
}

// Scorer is the model as a score.Scorer.
type Scorer struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex // guards tr, m, scr, firstData
	tr      *Tracker
	m       *model.Model
	scr     model.Scratch
	first   time.Time
	lastRun time.Time
}

var _ score.Scorer = (*Scorer)(nil)

// New builds a scorer, loading a saved model if one exists.
func New(cfg Config) (*Scorer, error) {
	if cfg.Explain == 0 {
		cfg.Explain = 3
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Nightly.Train.Batch == 0 {
		cfg.Nightly = model.DefaultNightlyConfig()
	}
	if cfg.RunHour == 0 {
		cfg.RunHour = 3
	}
	s := &Scorer{cfg: cfg, log: cfg.Log, tr: NewTracker()}
	if cfg.ModelPath != "" {
		if m, err := model.Load(cfg.ModelPath, cfg.Prior); err == nil {
			s.m = m
		}
	}
	if s.m == nil {
		s.m = model.New(uint64(cfg.Now().UnixNano()))
		s.m.Prior = cfg.Prior
	}
	// Warm the tracker with recent history so "seen before" survives a restart.
	if cfg.History != nil {
		if rows, err := cfg.History.Since(cfg.Now().Add(-30 * 24 * time.Hour)); err == nil && len(rows) > 0 {
			mins := make([]event.Minute, len(rows))
			for i := range rows {
				mins[i] = rows[i].Minute
			}
			s.tr.Observe(mins)
			s.first = mins[0].Start
		}
	}
	return s, nil
}

// Name implements score.Scorer.
func (s *Scorer) Name() string { return "trafficam-model" }

// Phase is the gamified ramp from the design doc.
func (s *Scorer) phase(now time.Time) string {
	if s.first.IsZero() {
		return "Listening"
	}
	switch d := now.Sub(s.first).Hours() / 24; {
	case d < 4:
		return "Listening"
	case d < 11:
		return "Settling in"
	case d < 30:
		return "Watching"
	default:
		return "Guarding"
	}
}

// Score implements score.Scorer. Before the first training the model is
// silent (Listening); after it, a row alerts when its score passes the
// machine's self-set line.
func (s *Scorer) Score(_ context.Context, batch []event.Minute) ([]score.Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.first.IsZero() && len(batch) > 0 {
		s.first = batch[0].Start
	}
	flows := s.tr.Observe(batch)
	out := make([]score.Verdict, len(batch))
	phase := s.phase(s.cfg.Now())
	scale := 100 + s.m.Cfg.NewDestBump + s.m.Cfg.PriorMax
	for i := range flows {
		v := score.Verdict{Phase: phase}
		if s.m.Trained() {
			r := s.m.Score(&flows[i], &s.scr)
			v.Score = min(r.Score/scale, 1)
			v.Alert = r.Alert
			if r.Alert {
				for _, rs := range s.m.Explain(&flows[i], r, s.cfg.Explain) {
					v.Reasons = append(v.Reasons, rs.Text)
				}
			}
		}
		out[i] = v
	}
	return out, nil
}

// TrainNow runs one nightly job: read the 30-day history, train a candidate,
// gate it on the held-out day and swap it in only if it passes. It is safe to
// call while Score is running; scoring continues on the old model throughout.
func (s *Scorer) TrainNow(ctx context.Context) (model.NightlyReport, error) {
	var rep model.NightlyReport
	if s.cfg.History == nil {
		return rep, fmt.Errorf("modelscore: no history source")
	}
	now := s.cfg.Now()
	rows, err := s.cfg.History.Since(now.Add(-30 * 24 * time.Hour))
	if err != nil {
		return rep, err
	}
	rt := NewTracker()
	mins := make([]event.Minute, len(rows))
	for i := range rows {
		mins[i] = rows[i].Minute
	}
	flows := rt.Observe(mins)
	samples := make([]model.Sample, len(rows))
	for i := range rows {
		samples[i] = model.Sample{Flow: flows[i], Alerted: rows[i].Alerted}
	}
	s.mu.Lock()
	cur := s.m
	s.mu.Unlock()
	next, rep, err := cur.Nightly(samples, now, s.cfg.Nightly)
	if err != nil {
		return rep, err
	}
	s.log.Info("nightly model job", "accepted", rep.Accepted, "reason", rep.Reason, "rows", len(samples),
		"old_loss", rep.OldLoss, "new_loss", rep.NewLoss, "alert_line", rep.AlertLine)
	if rep.Accepted {
		next.Prior = s.cfg.Prior
		if s.cfg.ModelPath != "" {
			if err := next.Save(s.cfg.ModelPath); err != nil {
				return rep, err
			}
		}
		s.mu.Lock()
		s.m = next
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.lastRun = now
	s.mu.Unlock()
	return rep, nil
}

// Loop runs TrainNow once a night (at RunHour, local time) when Idle allows,
// until ctx ends. Failures are logged; the watcher is never affected.
func (s *Scorer) Loop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := s.cfg.Now()
		s.mu.Lock()
		due := now.Hour() == s.cfg.RunHour && now.Sub(s.lastRun) > 20*time.Hour
		s.mu.Unlock()
		if !due || (s.cfg.Idle != nil && !s.cfg.Idle()) {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("nightly model job panicked", "panic", r)
				}
			}()
			if _, err := s.TrainNow(ctx); err != nil {
				s.log.Error("nightly model job failed", "err", err)
			}
		}()
	}
}
