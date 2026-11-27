// Package lab replays recorded traffic through trafficam's real rules and
// model, as if a fresh install had been watching that PC from the first row,
// and measures what the user would have been shown.
//
// It answers "how many alerts a day would this machine get?" (false alarms
// on a clean recording), and is the engine behind the attack tests and the
// threshold tuning. Nothing here is used by the live watcher.
//
// Faithfulness: the replay uses the same rules.Scorer, baseline counters and
// modelscore.Scorer as "trafficam live". The differences are deliberate and
// small:
//   - the clock is the recording's own time, not the wall clock;
//   - the baseline counters live in memory instead of the database (counted
//     identically; a test checks this against the real store);
//   - the nightly training runs at TrainHour every replayed day, without the
//     "only when idle and on mains power" check.
package lab

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/baseline"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/modelscore"
	"github.com/Venkatesan7G/trafficam/internal/rules"
	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Arm is one way of running trafficam over the same recording, e.g.
// "rules only" or "rules + model".
type Arm struct {
	Name  string
	Model bool         // run the learning model next to the rules
	Prior *model.HeadC // head C (only with Model); nil = off
	// Rules carries the thresholds and the user's lists. Baseline and Now
	// are filled in by the lab.
	Rules rules.Config
}

// Options control a replay.
type Options struct {
	TrainHour int            // local hour of the nightly job [3]
	Loc       *time.Location // time zone for TrainHour and day boundaries [time.Local]
	Nightly   model.NightlyConfig
	// ModelVerdicts, if set, replaces running the model: verdict i is used
	// for row i. Tuning uses this to rerun only the rules (see Reuse).
	ModelVerdicts []score.Verdict
	Progress      func(msg string) // optional status lines
}

// Kinds of alert, by what raised it.
const (
	KindBlocklist  = "known-bad"
	KindWatch      = "watch-list"
	KindNewProgram = "new-program"
	KindNewDest    = "new-destination"
	KindModel      = "model"
	KindOther      = "other"
)

// RowResult is what trafficam decided about one row.
type RowResult struct {
	Alert   bool
	Score   float64
	Phase   string
	Kinds   []string // why it alerted (empty when it did not)
	Reasons []string
}

// Training is one replayed nightly job.
type Training struct {
	At     time.Time
	Rows   int
	Report model.NightlyReport
	Err    string
}

// Result is a replay of one arm.
type Result struct {
	Arm       string
	Data      *Data
	Out       []RowResult     // one per Data.Rows entry
	Model     []score.Verdict // the model's own verdicts (nil without the model)
	Trainings []Training
	Loc       *time.Location
	Took      time.Duration
}

// Run replays d through one arm.
func Run(ctx context.Context, d *Data, arm Arm, opt Options) (*Result, error) {
	if opt.Loc == nil {
		opt.Loc = time.Local
	}
	if opt.TrainHour == 0 {
		opt.TrainHour = 3
	}
	if opt.Nightly.Train.Batch == 0 {
		opt.Nightly = model.DefaultNightlyConfig()
	}
	progress := opt.Progress
	if progress == nil {
		progress = func(string) {}
	}
	t0 := time.Now()
	res := &Result{Arm: arm.Name, Data: d, Out: make([]RowResult, len(d.Rows)), Loc: opt.Loc}
	if len(d.Rows) == 0 {
		return res, nil
	}

	var now time.Time
	clock := func() time.Time { return now }
	mem := newMemSeen(d.InstallTime())
	hist := &memHistory{}

	var learner *modelscore.Scorer
	rec := &recorder{}
	var inner score.Scorer = score.Nop{}
	switch {
	case opt.ModelVerdicts != nil:
		if len(opt.ModelVerdicts) != len(d.Rows) {
			return nil, fmt.Errorf("lab: %d reused model verdicts for %d rows", len(opt.ModelVerdicts), len(d.Rows))
		}
		rec.fixed = opt.ModelVerdicts
		inner = rec
	case arm.Model:
		var err error
		learner, err = modelscore.New(modelscore.Config{
			History: hist, Prior: arm.Prior, Nightly: opt.Nightly, Now: clock,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			return nil, err
		}
		rec.inner = learner
		inner = rec
	}
	rc := arm.Rules
	rc.Baseline = &baseline.Tracker{B: mem}
	rc.Now = clock
	sc, err := rules.NewScorer(rc, inner)
	if err != nil {
		return nil, err
	}
	var scoreErr error
	sc.OnError = func(e error) { scoreErr = e }

	nextTrain := nextAt(d.Rows[0].Start, opt.TrainHour, opt.Loc)
	lastDay := ""
	for i := 0; i < len(d.Rows); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		j := i + 1
		for j < len(d.Rows) && d.Rows[j].Start.Equal(d.Rows[i].Start) {
			j++
		}
		batch := d.Rows[i:j]
		// Live, a minute row is scored shortly after the minute closes.
		now = batch[0].Start.Add(time.Minute)

		for learner != nil && !now.Before(nextTrain) {
			at := nextTrain
			saved := now
			now = at
			rep, err := learner.TrainNow(ctx)
			tr := Training{At: at, Report: rep}
			if rows, _ := hist.Since(at.Add(-30 * 24 * time.Hour)); rows != nil {
				tr.Rows = len(rows)
			}
			if err != nil {
				tr.Err = err.Error()
			}
			res.Trainings = append(res.Trainings, tr)
			now = saved
			nextTrain = nextAt(at.Add(time.Minute), opt.TrainHour, opt.Loc)
		}
		if day := now.In(opt.Loc).Format("2006-01-02"); day != lastDay {
			lastDay = day
			progress(fmt.Sprintf("%s: %s", arm.Name, day))
		}

		rec.at = i
		vs, err := sc.Score(ctx, batch)
		if err != nil {
			return nil, err
		}
		if scoreErr != nil {
			return nil, fmt.Errorf("lab: scoring at %s: %w", now.Format(time.RFC3339), scoreErr)
		}
		for k, v := range vs {
			r := &res.Out[i+k]
			r.Alert, r.Score, r.Phase, r.Reasons = v.Alert, v.Score, v.Phase, v.Reasons
			if v.Alert {
				var mv *score.Verdict
				if rec.last != nil {
					mv = &rec.last[k]
				}
				r.Kinds = kindsOf(v, mv)
			}
			sv := v.Score
			hist.rows = append(hist.rows, store.Scored{Minute: batch[k], Score: &sv, Alerted: v.Alert})
		}
		if rec.last != nil {
			res.Model = append(res.Model, rec.last...)
		}
		i = j
	}
	res.Took = time.Since(t0)
	return res, nil
}

// nextAt is the first time at or after t whose local hour is hour:00.
func nextAt(t time.Time, hour int, loc *time.Location) time.Time {
	l := t.In(loc)
	c := time.Date(l.Year(), l.Month(), l.Day(), hour, 0, 0, 0, loc)
	if c.Before(t) {
		c = c.AddDate(0, 0, 1)
	}
	return c
}

// recorder sits between the rules and the model and keeps the model's own
// verdicts, so the lab can tell which alerts came from the model.
type recorder struct {
	inner score.Scorer
	fixed []score.Verdict // reused verdicts instead of inner
	at    int             // index of the batch's first row
	last  []score.Verdict
}

func (r *recorder) Name() string { return "lab-recorder" }

func (r *recorder) Score(ctx context.Context, batch []event.Minute) ([]score.Verdict, error) {
	if r.fixed != nil {
		r.last = append([]score.Verdict(nil), r.fixed[r.at:r.at+len(batch)]...)
		return append([]score.Verdict(nil), r.last...), nil
	}
	v, err := r.inner.Score(ctx, batch)
	if err != nil {
		r.last = make([]score.Verdict, len(batch))
		return nil, err
	}
	r.last = append([]score.Verdict(nil), v...)
	return v, nil
}

// kindsOf names what raised an alert. Model reasons are known exactly (the
// recorder kept them); everything else is a rule, recognised by its wording
// in package rules (TestRuleWording pins it).
func kindsOf(v score.Verdict, mv *score.Verdict) []string {
	var kinds []string
	add := func(k string) {
		if !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	if mv != nil && mv.Alert {
		add(KindModel)
	}
	for _, r := range v.Reasons {
		if mv != nil && slices.Contains(mv.Reasons, r) {
			continue
		}
		switch {
		case strings.Contains(r, "known-bad list"):
			add(KindBlocklist)
		case strings.Contains(r, "on your watch list"):
			add(KindWatch)
		case strings.Contains(r, "used the network for the first time"):
			add(KindNewProgram)
		case strings.Contains(r, "has never contacted") && strings.Contains(r, "normally talks to only"):
			add(KindNewDest)
		default:
			add(KindOther)
		}
	}
	if len(kinds) == 0 {
		add(KindOther)
	}
	return kinds
}
