// Package rules holds the always-alert rules: simple, explainable checks that
// run next to the model and never depend on it being trained.
//
// Rules, in priority order:
//
//  1. Known-bad: destination is on the offline blocklist snapshot (opt-in).
//     Always alerts. The ignore list does NOT silence it.
//  2. Alert-anyway: destination is on the user's own watch list. Always alerts.
//  3. New program: a program that has never used the network before now does.
//     (Held back during the first-install learning window.)
//  4. New destination for a settled program: a program with few destinations
//     (<= MaxHostsForNovelty) and some history starts contacting a host it has
//     never contacted. Browsers and other high fan-out programs are left to
//     the model, which judges them against their own habits.
//
// The user's ignore list silences rules 3 and 4 (and the model) but never 1 or 2.
package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/baseline"
	"github.com/Venkatesan7G/trafficam/internal/blocklist"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/score"
)

// Config tunes the engine. Zero values give the defaults in brackets.
type Config struct {
	Blocklist   *blocklist.List // known-bad snapshot; nil = switched off
	AlertAnyway *blocklist.List // user "watch" list
	Ignore      *blocklist.List // user "ignore" list

	Baseline *baseline.Tracker // required

	InstallGrace       time.Duration // [48h] no novelty alerts while the install is younger
	MinProgramAge      time.Duration // [72h] a program must be this old before new-destination alerts
	MaxHostsForNovelty int           // [20] programs with more known destinations are left to the model
	DisableNewProgram  bool          // turn rule 3 off
	DisableNewHost     bool          // turn rule 4 off

	Now func() time.Time // [time.Now]; replaceable in tests
}

// Scorer runs the rules and an inner model scorer together and merges the
// answers: it alerts if either side would, and shows every reason.
// It also owns updating the baseline counters, after scoring each batch.
type Scorer struct {
	cfg   Config
	Model score.Scorer // [score.Nop]; the trained model plugs in here
	// OnError is told about non-fatal problems (model failed, baseline
	// unavailable). The rules still answer so alerts are never lost.
	OnError func(error)
}

func NewScorer(cfg Config, model score.Scorer) (*Scorer, error) {
	if cfg.Baseline == nil {
		return nil, fmt.Errorf("rules: Baseline is required")
	}
	if cfg.InstallGrace <= 0 {
		cfg.InstallGrace = 48 * time.Hour
	}
	if cfg.MinProgramAge <= 0 {
		cfg.MinProgramAge = 72 * time.Hour
	}
	if cfg.MaxHostsForNovelty <= 0 {
		cfg.MaxHostsForNovelty = 20
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if model == nil {
		model = score.Nop{}
	}
	return &Scorer{cfg: cfg, Model: model}, nil
}

func (s *Scorer) Name() string { return "rules+" + s.Model.Name() }

func (s *Scorer) report(err error) {
	if s.OnError != nil && err != nil {
		s.OnError(err)
	}
}

// Score implements score.Scorer.
func (s *Scorer) Score(ctx context.Context, batch []event.Minute) ([]score.Verdict, error) {
	out := make([]score.Verdict, len(batch))

	// 1. Model first (it may be slow or fail; rules must survive either).
	if mv, err := s.Model.Score(ctx, batch); err != nil || len(mv) != len(batch) {
		if err == nil {
			err = fmt.Errorf("model returned %d verdicts for %d rows", len(mv), len(batch))
		}
		s.report(fmt.Errorf("model scorer failed, using rules only: %w", err))
	} else {
		copy(out, mv)
	}

	// 2. Baseline history (before this batch is counted).
	infos, err := s.cfg.Baseline.Lookup(batch)
	haveBaseline := err == nil
	s.report(err)
	age, err := s.cfg.Baseline.InstallAge(s.cfg.Now())
	if err != nil {
		haveBaseline = false
		s.report(err)
	}
	pastGrace := haveBaseline && age >= s.cfg.InstallGrace

	// 3. Rules and merge. A novelty fact is reported once per batch, not once
	// per minute row, so a burst does not become a burst of notifications.
	told := map[string]bool{}
	for i, m := range batch {
		v := &out[i]
		forced := false

		if entry, ok := s.cfg.Blocklist.Match(m); ok {
			v.Score, v.Alert, forced = 1, true, true
			v.Reasons = append(v.Reasons, fmt.Sprintf("destination is on the known-bad list (%s)", entry))
		}
		if entry, ok := s.cfg.AlertAnyway.Match(m); ok {
			v.Score, v.Alert, forced = max(v.Score, 1), true, true
			v.Reasons = append(v.Reasons, fmt.Sprintf("destination is on your watch list (%s)", entry))
		}
		if forced {
			continue
		}

		if pastGrace && m.Host != "" && !s.cfg.Ignore.IsMatch(m) {
			if r := s.novelty(m, infos[i], told); r != "" {
				v.Alert = true
				v.Score = max(v.Score, 0.8)
				v.Reasons = append(v.Reasons, r)
			}
		}
		if _, ignored := s.cfg.Ignore.Match(m); ignored {
			v.Alert = false // user said this is fine; the score stays for the record
		}
	}

	// 4. Count the batch only now, so rules saw the history as it was before.
	s.report(s.cfg.Baseline.Update(batch))
	return out, nil
}

// novelty implements rules 3 and 4. It returns a reason or "".
func (s *Scorer) novelty(m event.Minute, in baseline.Info, told map[string]bool) string {
	if in.ProgramFirst.IsZero() {
		if !s.cfg.DisableNewProgram && !told["p|"+m.Program.Key()] {
			told["p|"+m.Program.Key()] = true
			return fmt.Sprintf("%s used the network for the first time (to %s)", m.Program.Name, m.Host)
		}
		return ""
	}
	if s.cfg.DisableNewHost || in.HostKnown {
		return ""
	}
	settled := s.cfg.Now().Sub(in.ProgramFirst) >= s.cfg.MinProgramAge
	if settled && in.ProgramHosts <= s.cfg.MaxHostsForNovelty && !told["h|"+m.Program.Key()+"|"+m.Host] {
		told["h|"+m.Program.Key()+"|"+m.Host] = true
		return fmt.Sprintf("%s has never contacted %s before (it normally talks to only %d places)",
			m.Program.Name, m.Host, in.ProgramHosts)
	}
	return ""
}
