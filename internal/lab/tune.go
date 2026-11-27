package lab

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/rules"
)

// The three novelty settings in package rules, and their shipped defaults.
var (
	DefaultGrace    = 48 * time.Hour // InstallGrace: no novelty alerts while the install is younger
	DefaultAge      = 72 * time.Hour // MinProgramAge: a program must be this old before new-destination alerts
	DefaultMaxHosts = 20             // MaxHostsForNovelty: programs with more destinations are left to the model
)

// Setting is one combination of the three thresholds.
type Setting struct {
	Grace    time.Duration
	Age      time.Duration
	MaxHosts int
}

func (s Setting) String() string {
	return fmt.Sprintf("grace %-4s age %-5s hosts %-3d", hours(s.Grace), hours(s.Age), s.MaxHosts)
}

func (s Setting) IsDefault() bool {
	return s.Grace == DefaultGrace && s.Age == DefaultAge && s.MaxHosts == DefaultMaxHosts
}

func hours(d time.Duration) string { return fmt.Sprintf("%dh", int(d.Hours())) }

// Grid lists every combination.
func Grid(graces, ages []time.Duration, hosts []int) []Setting {
	var out []Setting
	for _, g := range graces {
		for _, a := range ages {
			for _, h := range hosts {
				out = append(out, Setting{g, a, h})
			}
		}
	}
	return out
}

// TuneResult is one setting measured on one (labelled) recording.
type TuneResult struct {
	Setting
	Caught, Planted int
	Missed          []string
	// FalsePerDay is measured over the same days for every setting (from
	// the largest grace in the grid on), so settings compare fairly.
	FalsePerDay float64
	// Early is false alarms before that common start (the first days after
	// install): the price of a short grace or a short program age.
	Early int
	// FirstWeek is false alarms in the 7 days after that common start.
	FirstWeek int
}

// TuneOptions control Tune.
type TuneOptions struct {
	Options              // replay options (time zone, nightly config)
	Base    rules.Config // the user's lists; thresholds are overwritten
	Model   bool         // include the model's alerts (it runs once, then is reused)
	Prior   *model.HeadC // optional head C for the model run
	Log     func(string) // progress
}

// Tune replays the recording once per setting. With Model, the model runs
// once with the shipped thresholds and its verdicts are reused for every
// setting, so the sweep costs one model replay plus fast rules-only replays.
// (Approximation: the model's nightly training saw which rows alerted under
// the default thresholds. That feeds only its 3-day "don't learn from
// alerted rows" guard, a small effect.)
func Tune(ctx context.Context, d *Data, labels Labels, attacks []Attack, grid []Setting, opt TuneOptions) ([]TuneResult, error) {
	if len(grid) == 0 {
		return nil, fmt.Errorf("lab: empty tuning grid")
	}
	log := opt.Log
	if log == nil {
		log = func(string) {}
	}
	if labels == nil {
		labels = make(Labels, len(d.Rows))
	}
	var maxGrace time.Duration
	for _, s := range grid {
		maxGrace = max(maxGrace, s.Grace)
	}
	o := opt.Options
	if opt.Model {
		log("running the model once with the shipped thresholds")
		arm := Arm{Name: "model", Model: true, Prior: opt.Prior, Rules: opt.Base}
		r, err := Run(ctx, d, arm, o)
		if err != nil {
			return nil, err
		}
		o.ModelVerdicts = r.Model
	}
	from := d.InstallTime().Add(maxGrace)
	var out []TuneResult
	for i, s := range grid {
		if i%10 == 0 {
			log(fmt.Sprintf("setting %d of %d", i+1, len(grid)))
		}
		rc := opt.Base
		rc.InstallGrace, rc.MinProgramAge, rc.MaxHostsForNovelty = s.Grace, s.Age, s.MaxHosts
		r, err := Run(ctx, d, Arm{Name: s.String(), Rules: rc}, o)
		if err != nil {
			return nil, err
		}
		sc := Score(r, labels, attacks, s.Grace)
		tr := TuneResult{Setting: s, Caught: sc.Caught, Planted: sc.Planted}
		for k, oc := range sc.Outcomes {
			if !oc.Caught {
				tr.Missed = append(tr.Missed, attacks[k].ID)
			}
		}
		var n, days int
		for _, ds := range sc.Summary.Days {
			start, _ := time.ParseInLocation("2006-01-02", ds.Day, r.Loc)
			if start.Before(from) {
				tr.Early += ds.Events
				continue
			}
			days++
			n += ds.Events
			if start.Before(from.Add(7 * 24 * time.Hour)) {
				tr.FirstWeek += ds.Events
			}
		}
		if days > 0 {
			tr.FalsePerDay = float64(n) / float64(days)
		}
		out = append(out, tr)
	}
	return out, nil
}

// Rank orders results best first: most attacks caught ("no misses" comes
// before "few false alarms"), then fewest false alarms per day, then fewest
// in the first days after install, then the shortest grace and age (alerts sooner), then
// the most hosts (rule covers more programs).
func Rank(rs []TuneResult) []TuneResult {
	out := append([]TuneResult(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Caught != b.Caught:
			return a.Caught > b.Caught
		case a.FalsePerDay != b.FalsePerDay:
			return a.FalsePerDay < b.FalsePerDay
		case a.Early+a.FirstWeek != b.Early+b.FirstWeek:
			return a.Early+a.FirstWeek < b.Early+b.FirstWeek
		case a.Grace != b.Grace:
			return a.Grace < b.Grace
		case a.Age != b.Age:
			return a.Age < b.Age
		default:
			return a.MaxHosts > b.MaxHosts
		}
	})
	return out
}

// WriteTuning prints the ranked table, where the shipped defaults land, and
// how each knob on its own moves the numbers.
func WriteTuning(w io.Writer, d *Data, attacks []Attack, rs []TuneResult, withModel bool, top int) {
	ranked := Rank(rs)
	what := "rules only"
	if withModel {
		what = "rules + model (model run once, reused)"
	}
	fmt.Fprintf(w, "trafficam threshold tuning (%s)\n  data: %s, %d days\n  %d settings, %d planted attacks\n", what, d.Source, d.Days(), len(rs), len(attacks))
	fmt.Fprintln(w, "  false/day: false alarms per day once past the longest grace tried (same days for every setting).")
	fmt.Fprintln(w, "  early: false alarms before that, i.e. right after install. first week: the 7 days after that.")
	fmt.Fprintf(w, "\n  %-4s %-28s %8s %10s %6s %11s  %s\n", "rank", "setting", "caught", "false/day", "early", "first week", "missed")
	defRank := -1
	for i, r := range ranked {
		if r.IsDefault() {
			defRank = i
		}
		if i >= top && !r.IsDefault() {
			continue
		}
		mark := ""
		if r.IsDefault() {
			mark = "  <- shipped default"
		}
		fmt.Fprintf(w, "  %-4d %-28s %3d/%-4d %10.2f %6d %11d  %s%s\n", i+1, r.Setting, r.Caught, r.Planted, r.FalsePerDay, r.Early, r.FirstWeek, list(r.Missed), mark)
	}
	best := ranked[0]
	fmt.Fprintf(w, "\nBest: %s  (%d/%d caught, %.2f false alarms/day)\n", best.Setting, best.Caught, best.Planted, best.FalsePerDay)
	if defRank >= 0 {
		def := ranked[defRank]
		fmt.Fprintf(w, "Shipped default ranks %d of %d (%d/%d caught, %.2f false alarms/day).\n", defRank+1, len(ranked), def.Caught, def.Planted, def.FalsePerDay)
		if def.Caught == best.Caught && def.FalsePerDay-best.FalsePerDay < 0.1 {
			fmt.Fprintln(w, "  The default is as good as the best on this recording: no reason to change it from this data.")
		}
	}
	fmt.Fprintln(w, "One recording is not enough to change a default. Compare the best settings across several machines.")

	// One knob at a time, others at their defaults.
	fmt.Fprintln(w, "\nEach knob on its own (the other two at their defaults):")
	knob := func(name string, keep func(Setting) bool, val func(Setting) string) {
		var row []TuneResult
		for _, r := range rs {
			if keep(r.Setting) {
				row = append(row, r)
			}
		}
		if len(row) < 2 {
			return
		}
		fmt.Fprintf(w, "  %s\n", name)
		for _, r := range row {
			fmt.Fprintf(w, "    %-5s %2d caught, %.2f false/day, %d early\n", val(r.Setting), r.Caught, r.FalsePerDay, r.Early)
		}
	}
	knob("grace", func(s Setting) bool { return s.Age == DefaultAge && s.MaxHosts == DefaultMaxHosts },
		func(s Setting) string { return hours(s.Grace) })
	knob("program age", func(s Setting) bool { return s.Grace == DefaultGrace && s.MaxHosts == DefaultMaxHosts },
		func(s Setting) string { return hours(s.Age) })
	knob("max hosts", func(s Setting) bool { return s.Grace == DefaultGrace && s.Age == DefaultAge },
		func(s Setting) string { return fmt.Sprint(s.MaxHosts) })
}
