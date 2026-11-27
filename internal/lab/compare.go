package lab

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Outcome is how one arm did against one planted attack.
type Outcome struct {
	Attack    string
	Caught    bool
	Delay     time.Duration // attack start -> first alert on one of its rows
	AlertRows int           // alerted rows of the attack
	Kinds     []string      // what raised the alerts
}

// Scorecard is one arm on one labelled recording.
type Scorecard struct {
	Arm      string
	Outcomes []Outcome
	Caught   int
	Planted  int
	FalsePer float64 // false alarms per steady day (attack rows excluded)
	Summary  *Summary
}

// Score compares one replay with the planted attacks.
func Score(r *Result, labels Labels, attacks []Attack, grace time.Duration) *Scorecard {
	sc := &Scorecard{Arm: r.Arm, Planted: len(attacks)}
	by := map[string]*Outcome{}
	for _, a := range attacks {
		sc.Outcomes = append(sc.Outcomes, Outcome{Attack: a.ID})
	}
	for i := range sc.Outcomes {
		by[sc.Outcomes[i].Attack] = &sc.Outcomes[i]
	}
	start := map[string]time.Time{}
	for _, a := range attacks {
		start[a.ID] = a.Start
	}
	for i, l := range labels {
		if l == "" || !r.Out[i].Alert {
			continue
		}
		o := by[l]
		if o == nil {
			continue
		}
		if !o.Caught {
			o.Caught = true
			o.Delay = max(r.Data.Rows[i].Start.Sub(start[l].Truncate(time.Minute)), 0)
		}
		o.AlertRows++
		for _, k := range r.Out[i].Kinds {
			if !contains(o.Kinds, k) {
				o.Kinds = append(o.Kinds, k)
			}
		}
	}
	for _, o := range sc.Outcomes {
		if o.Caught {
			sc.Caught++
		}
	}
	sc.Summary = SummariseLabelled(r, grace, labels)
	sc.FalsePer = sc.Summary.SteadyPerDay
	return sc
}

// WriteComparison prints the side-by-side table: which arm caught which
// attack, how fast, and at what false-alarm cost. The last section says what
// the model added over the rules alone.
func WriteComparison(w io.Writer, d *Data, attacks []Attack, cards []*Scorecard) {
	fmt.Fprintf(w, "trafficam attack test\n  data: %s\n  %d planted attacks, %d days, %d rows\n\n", d.Source, len(attacks), d.Days(), len(d.Rows))
	fmt.Fprintf(w, "Planted attacks\n")
	for _, a := range attacks {
		hard := ""
		if a.Hard {
			hard = " [hard for rules]"
		}
		fmt.Fprintf(w, "  %-15s %s  %4d rows  %s%s\n", a.ID, a.Start.Format("01-02 15:04"), a.Rows, a.What, hard)
		fmt.Fprintf(w, "  %-15s runs as %s\n", "", a.Program)
	}

	fmt.Fprintf(w, "\nResults (caught = at least one alert on the attack's rows; delay = start to first alert)\n  %-15s", "attack")
	for _, c := range cards {
		fmt.Fprintf(w, " | %-30s", c.Arm)
	}
	fmt.Fprintln(w)
	for i, a := range attacks {
		fmt.Fprintf(w, "  %-15s", a.ID)
		for _, c := range cards {
			o := c.Outcomes[i]
			cell := "missed"
			if o.Caught {
				cell = fmt.Sprintf("caught %-7s %s", shortDur(o.Delay), strings.Join(o.Kinds, ","))
			}
			fmt.Fprintf(w, " | %-30s", cell)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  %-15s", "TOTAL")
	for _, c := range cards {
		fmt.Fprintf(w, " | %-30s", fmt.Sprintf("%d/%d caught", c.Caught, c.Planted))
	}
	fmt.Fprintf(w, "\n  %-15s", "false alarms/day")
	for _, c := range cards {
		fmt.Fprintf(w, " | %-30s", fmt.Sprintf("%.2f (steady days: %d)", c.FalsePer, c.Summary.SteadyDays))
	}
	fmt.Fprintln(w)

	// What did the model add? Compare each arm with the first one (rules only, by convention).
	if len(cards) < 2 {
		return
	}
	base := cards[0]
	for _, c := range cards[1:] {
		var gained, lost []string
		for i := range attacks {
			b, o := base.Outcomes[i], c.Outcomes[i]
			switch {
			case o.Caught && !b.Caught:
				gained = append(gained, attacks[i].ID)
			case b.Caught && !o.Caught:
				lost = append(lost, attacks[i].ID)
			}
		}
		var faster []string
		for i := range attacks {
			b, o := base.Outcomes[i], c.Outcomes[i]
			if b.Caught && o.Caught && o.Delay+time.Minute < b.Delay {
				faster = append(faster, fmt.Sprintf("%s (%s instead of %s)", attacks[i].ID, shortDur(o.Delay), shortDur(b.Delay)))
			}
		}
		sort.Strings(gained)
		fmt.Fprintf(w, "\n%s vs %s\n", c.Arm, base.Arm)
		fmt.Fprintf(w, "  extra attacks caught: %d %s\n", len(gained), list(gained))
		fmt.Fprintf(w, "  caught sooner:        %d %s\n", len(faster), list(faster))
		if len(lost) > 0 {
			fmt.Fprintf(w, "  LOST (rules caught, this arm did not): %s\n", list(lost))
		}
		fmt.Fprintf(w, "  false alarms/day:     %.2f -> %.2f\n", base.FalsePer, c.FalsePer)
		switch {
		case len(gained) == 0 && len(faster) == 0:
			fmt.Fprintln(w, "  verdict: the model added nothing on this recording.")
		case c.FalsePer > base.FalsePer+1.5:
			fmt.Fprintln(w, "  verdict: the model catches more but costs over 1.5 extra false alarms a day.")
		default:
			fmt.Fprintln(w, "  verdict: the model adds detections within the false-alarm budget.")
		}
	}
}

func list(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return "(" + strings.Join(xs, ", ") + ")"
}

func shortDur(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
}

// WriteFalseAlarmSources lists, per arm, which programs the false alarms
// came from and the most common first reason, so a storm has a visible cause.
func WriteFalseAlarmSources(w io.Writer, cards []*Scorecard, private bool) {
	salt := fmt.Sprint(time.Now().UnixNano())
	for _, c := range cards {
		if len(c.Summary.Events) == 0 {
			continue
		}
		type agg struct {
			n       int
			reasons map[string]int
		}
		by := map[string]*agg{}
		for _, e := range c.Summary.Events {
			a := by[e.Program]
			if a == nil {
				a = &agg{reasons: map[string]int{}}
				by[e.Program] = a
			}
			a.n++
			a.reasons[genericReason(e.Reason, e.Program, e.Host)]++
		}
		progs := make([]string, 0, len(by))
		for p := range by {
			progs = append(progs, p)
		}
		sort.Slice(progs, func(i, j int) bool {
			return by[progs[i]].n > by[progs[j]].n || (by[progs[i]].n == by[progs[j]].n && progs[i] < progs[j])
		})
		fmt.Fprintf(w, "\n%s: where the %d false alarms came from\n", c.Arm, len(c.Summary.Events))
		for _, p := range progs[:min(5, len(progs))] {
			a := by[p]
			top, tn := "", 0
			for r, n := range a.reasons {
				if n > tn || (n == tn && r < top) {
					top, tn = r, n
				}
			}
			name := p
			if private {
				name, top = Anon(salt, p), ""
			}
			fmt.Fprintf(w, "  %5d  %-40s %s\n", a.n, short(name, 40), top)
		}
	}
}

// genericReason strips the program and host out of a reason so that the
// same cause on different destinations groups together.
func genericReason(r, prog, host string) string {
	r = strings.ReplaceAll(r, prog, "PROGRAM")
	if host != "" {
		r = strings.ReplaceAll(r, host, "HOST")
	}
	return numbers.ReplaceAllString(r, "N")
}
