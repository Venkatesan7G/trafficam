package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// An alert event is what the user would actually notice: the first alerted
// row for a (program, destination) pair on a given day. A beacon that trips
// 200 minute rows in one day is one event, and is counted once.
type AlertEvent struct {
	Day     string // local date
	First   time.Time
	Program string
	Host    string
	Port    uint16
	Rows    int // alerted minute rows folded into this event
	Kinds   []string
	Reason  string // first reason shown
	RowIdx  int    // index of the first alerted row in Data.Rows
}

// DayStats is one replayed day.
type DayStats struct {
	Day        string
	Phase      string
	Rows       int
	AlertRows  int
	Events     int
	ByKind     map[string]int // events per kind (an event can have several kinds)
	Trained    bool           // a nightly job ran and was accepted on this day
	ModelReady bool           // the model had a trained model by the end of the day
}

// Summary condenses one arm's replay.
type Summary struct {
	Arm           string
	Days          []DayStats
	Events        []AlertEvent
	TotalEvents   int
	EventsPerDay  float64 // over all days
	SteadyPerDay  float64 // over days after the install grace and the first model (what an established install sees)
	SteadyDays    int
	WorstDay      string
	WorstDayCount int
	Trainings     []Training
	Loc           *time.Location
}

// Summarise turns a replay into per-day numbers and alert events.
func Summarise(r *Result, installGrace time.Duration) *Summary {
	return SummariseLabelled(r, installGrace, nil)
}

// SummariseLabelled is Summarise for data with planted attacks: rows with a
// label are left out of the alert counts, so the numbers are false alarms
// only. (Attack rows still count as rows of the day.)
func SummariseLabelled(r *Result, installGrace time.Duration, labels Labels) *Summary {
	if installGrace <= 0 {
		installGrace = 48 * time.Hour
	}
	s := &Summary{Arm: r.Arm, Trainings: r.Trainings, Loc: r.Loc}
	byDay := map[string]*DayStats{}
	var order []string
	ev := map[string]int{} // day|prog|host|port -> index in s.Events
	for i, m := range r.Data.Rows {
		day := m.Start.In(r.Loc).Format("2006-01-02")
		ds := byDay[day]
		if ds == nil {
			ds = &DayStats{Day: day, ByKind: map[string]int{}}
			byDay[day] = ds
			order = append(order, day)
		}
		ds.Rows++
		o := r.Out[i]
		if o.Phase != "" {
			ds.Phase = o.Phase
		}
		if !o.Alert || (labels != nil && labels[i] != "") {
			continue
		}
		ds.AlertRows++
		k := fmt.Sprintf("%s|%s|%s|%d", day, m.Program.Key(), m.Host, m.Port)
		if j, ok := ev[k]; ok {
			s.Events[j].Rows++
			for _, kind := range o.Kinds {
				if !contains(s.Events[j].Kinds, kind) {
					s.Events[j].Kinds = append(s.Events[j].Kinds, kind)
				}
			}
			continue
		}
		e := AlertEvent{Day: day, First: m.Start, Program: m.Program.Key(), Host: m.Host, Port: m.Port, Rows: 1,
			Kinds: append([]string(nil), o.Kinds...), RowIdx: i}
		if len(o.Reasons) > 0 {
			e.Reason = o.Reasons[0]
		}
		ev[k] = len(s.Events)
		s.Events = append(s.Events, e)
	}
	for _, e := range s.Events {
		ds := byDay[e.Day]
		ds.Events++
		for _, k := range e.Kinds {
			ds.ByKind[k]++
		}
	}
	modelReady := false
	for _, t := range r.Trainings {
		if t.Report.Accepted {
			d := t.At.In(r.Loc).Format("2006-01-02")
			if ds := byDay[d]; ds != nil {
				ds.Trained = true
			}
		}
	}
	install := r.Data.InstallTime()
	var steady int
	for _, d := range order {
		ds := byDay[d]
		if ds.Trained {
			modelReady = true
		}
		ds.ModelReady = modelReady
		s.Days = append(s.Days, *ds)
		s.TotalEvents += ds.Events
		if ds.Events > s.WorstDayCount {
			s.WorstDay, s.WorstDayCount = d, ds.Events
		}
		dayStart, _ := time.ParseInLocation("2006-01-02", d, r.Loc)
		// "Steady" days: the whole day is past the install grace, and (for
		// arms with the model) a trained model existed from the start of it.
		if dayStart.Sub(install) >= installGrace && (r.Model == nil || modelReadyBefore(r, dayStart)) {
			s.SteadyDays++
			steady += ds.Events
		}
	}
	if n := len(s.Days); n > 0 {
		s.EventsPerDay = float64(s.TotalEvents) / float64(n)
	}
	if s.SteadyDays > 0 {
		s.SteadyPerDay = float64(steady) / float64(s.SteadyDays)
	}
	return s
}

func modelReadyBefore(r *Result, t time.Time) bool {
	for _, tr := range r.Trainings {
		if tr.Report.Accepted && !tr.At.After(t) {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ReportOptions control the text report.
type ReportOptions struct {
	// Private replaces program paths and hosts with short hashes, so the
	// report can be shared without saying where this PC connects. Counts
	// are unchanged.
	Private bool
	TopN    int // alert events listed at the end [15]
}

// Anon hashes a name for a private report (stable within one report run).
func Anon(salt, s string) string {
	h := sha256.Sum256([]byte(salt + "\x00" + s))
	return "h-" + hex.EncodeToString(h[:4])
}

// WriteText prints a human-readable report of one or more arms on the same data.
func WriteText(w io.Writer, d *Data, sums []*Summary, opt ReportOptions) {
	if opt.TopN == 0 {
		opt.TopN = 15
	}
	salt := fmt.Sprint(time.Now().UnixNano())
	name := func(s string) string {
		if opt.Private {
			return Anon(salt, s)
		}
		return s
	}
	progs := map[string]bool{}
	for _, m := range d.Rows {
		progs[m.Program.Key()] = true
	}
	fmt.Fprintf(w, "trafficam replay report\n")
	fmt.Fprintf(w, "  data: %s\n  rows: %d minute rows, %d programs, %d days", d.Source, len(d.Rows), len(progs), d.Days())
	if len(d.Rows) > 0 {
		fmt.Fprintf(w, " (%s to %s)", d.Rows[0].Start.Format("2006-01-02 15:04"), d.Rows[len(d.Rows)-1].Start.Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  An \"alert\" below is one notification: the first alert for a program and destination on a day.")
	fmt.Fprintln(w, "  On a clean recording every alert is a false alarm. Read the list at the end and note any that were real.")

	fmt.Fprintf(w, "\nSummary\n  %-22s %8s %10s %12s %14s %s\n", "arm", "alerts", "per day", "steady/day", "steady days", "worst day")
	for _, s := range sums {
		fmt.Fprintf(w, "  %-22s %8d %10.2f %12.2f %14d %s (%d)\n", s.Arm, s.TotalEvents, s.EventsPerDay, s.SteadyPerDay, s.SteadyDays, s.WorstDay, s.WorstDayCount)
	}
	fmt.Fprintln(w, "  steady/day = alerts per day once past the 48 h install grace and (with the model) after its first training.")

	for _, s := range sums {
		fmt.Fprintf(w, "\n%s: per day\n  %-10s %-12s %7s %7s  %s\n", s.Arm, "day", "phase", "rows", "alerts", "by kind")
		for _, ds := range s.Days {
			var kinds []string
			for k, n := range ds.ByKind {
				kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
			}
			sort.Strings(kinds)
			mark := ""
			if ds.Trained {
				mark = "  [model trained]"
			}
			fmt.Fprintf(w, "  %-10s %-12s %7d %7d  %s%s\n", ds.Day, ds.Phase, ds.Rows, ds.Events, strings.Join(kinds, " "), mark)
		}
		var acc, tried int
		why := map[string]int{}
		for _, t := range s.Trainings {
			tried++
			if t.Report.Accepted {
				acc++
			} else {
				r := t.Report.Reason
				if t.Err != "" {
					r = "error: " + t.Err
				}
				why[numbers.ReplaceAllString(r, "N")]++
			}
		}
		if tried > 0 {
			fmt.Fprintf(w, "  nightly jobs: %d run, %d accepted\n", tried, acc)
			for r, n := range why {
				fmt.Fprintf(w, "    kept the old model %d times: %s\n", n, r)
			}
		}
	}

	for _, s := range sums {
		if len(s.Events) == 0 {
			continue
		}
		ev := append([]AlertEvent(nil), s.Events...)
		// Programs that alert most are what to look at first.
		perProg := map[string]int{}
		for _, e := range ev {
			perProg[e.Program]++
		}
		sort.SliceStable(ev, func(i, j int) bool {
			if perProg[ev[i].Program] != perProg[ev[j].Program] {
				return perProg[ev[i].Program] > perProg[ev[j].Program]
			}
			return ev[i].First.Before(ev[j].First)
		})
		fmt.Fprintf(w, "\n%s: alerts to review (top %d of %d)\n", s.Arm, min(opt.TopN, len(ev)), len(ev))
		for _, e := range ev[:min(opt.TopN, len(ev))] {
			reason := e.Reason
			if opt.Private {
				reason = ""
			}
			fmt.Fprintf(w, "  %s %-28s -> %-30s :%-5d %-26s %s\n", e.First.In(s.Loc).Format("01-02 15:04"),
				short(name(e.Program), 28), short(name(e.Host), 30), e.Port, strings.Join(e.Kinds, ","), reason)
		}
	}
}

var numbers = regexp.MustCompile(`[0-9]+(\.[0-9]+)?`)

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n+1:]
}
