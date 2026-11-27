package lab

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/baseline"
	"github.com/Venkatesan7G/trafficam/internal/blocklist"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/rules"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

var t0 = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// The in-memory counters must agree with the real database on every query
// the rules make, or the replay would not be measuring trafficam.
func TestMemSeenMatchesStore(t *testing.T) {
	d := Synthetic(t0, 4, 1)
	st := openTestStore(t)
	mem := newMemSeen(t0)
	for i := 0; i < len(d.Rows); i += 200 {
		b := d.Rows[i:min(i+200, len(d.Rows))]
		if err := st.SeenUpdate(b); err != nil {
			t.Fatal(err)
		}
		mem.SeenUpdate(b)
	}
	var keys []store.SeenKey
	progs := map[string]bool{}
	for _, m := range d.Rows {
		keys = append(keys, store.KeyOf(m))
		progs[m.Program.Key()] = true
	}
	keys = append(keys, store.SeenKey{Prog: "nobody", Host: "nowhere"})
	a, _ := st.SeenGet(keys)
	b, _ := mem.SeenGet(keys)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("seen tables differ: store %d pairs, memory %d pairs", len(a), len(b))
	}
	progs["nobody"] = true
	for p := range progs {
		f1, h1, _ := st.ProgramSummary(p)
		f2, h2, _ := mem.ProgramSummary(p)
		if !f1.Equal(f2) || h1 != h2 {
			t.Errorf("%s: store (%v, %d) memory (%v, %d)", p, f1, h1, f2, h2)
		}
	}
}

// kindsOf recognises rule alerts by their wording in package rules. If that
// wording changes, this test fails instead of the report silently saying
// "other".
func TestRuleWording(t *testing.T) {
	bl := blocklist.New()
	bl.Add("bad.example")
	watch := blocklist.New()
	watch.Add("watched.example")
	mem := newMemSeen(t0.Add(-100 * time.Hour))
	now := t0
	sc, err := rules.NewScorer(rules.Config{Blocklist: bl, AlertAnyway: watch, Now: func() time.Time { return now }}, nil)
	if err == nil {
		t.Fatal("NewScorer should insist on a baseline")
	}
	cfg := rules.Config{Blocklist: bl, AlertAnyway: watch, Now: func() time.Time { return now }}
	cfg.Baseline = &baseline.Tracker{B: mem}
	sc, _ = rules.NewScorer(cfg, nil)
	row := func(prog, host string) event.Minute {
		return event.Minute{Start: now, Program: event.Program{Name: prog}, Host: host, Proto: event.TCP, Dir: event.Outbound, Port: 443, Flows: 1}
	}
	old := row("app", "home.example")
	old.Start = t0.Add(-96 * time.Hour)
	mem.SeenUpdate([]event.Minute{old})

	cases := []struct {
		m    event.Minute
		want string
	}{
		{row("app", "bad.example"), KindBlocklist},
		{row("app", "watched.example"), KindWatch},
		{row("newapp", "x.example"), KindNewProgram},
		{row("app", "elsewhere.example"), KindNewDest},
	}
	for _, c := range cases {
		v, err := sc.Score(context.Background(), []event.Minute{c.m})
		if err != nil || !v[0].Alert {
			t.Fatalf("%s: no alert (%v)", c.m.Host, err)
		}
		if got := kindsOf(v[0], nil); len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: kinds %v, want %s (reasons %q)", c.m.Host, got, c.want, v[0].Reasons)
		}
	}
}

func TestRunRulesOnly(t *testing.T) {
	d := Synthetic(t0, 6, 2)
	r, err := Run(context.Background(), d, Arm{Name: "rules"}, Options{Loc: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	s := Summarise(r, 0)
	if len(s.Days) != 6 {
		t.Fatalf("%d days, want 6", len(s.Days))
	}
	// Nothing in the 48 h grace.
	if s.Days[0].Events+s.Days[1].Events != 0 {
		t.Errorf("alerts during the install grace: %+v %+v", s.Days[0], s.Days[1])
	}
	// The editor is installed on day 3 (index 3): one new-program alert.
	if s.Days[3].ByKind[KindNewProgram] != 1 {
		t.Errorf("day 3: want 1 new-program alert, got %v", s.Days[3].ByKind)
	}
	for _, e := range s.Events {
		if e.Program == "/usr/lib/firefox/firefox" && contains(e.Kinds, KindNewDest) {
			t.Errorf("browser has hundreds of sites; the new-destination rule should leave it alone: %+v", e)
		}
	}
	var sb strings.Builder
	WriteText(&sb, d, []*Summary{s}, ReportOptions{})
	if !strings.Contains(sb.String(), "steady/day") {
		t.Error("report is missing its summary")
	}
	t.Log("\n" + sb.String())
}

// One replay with the real model, kept small so it stays a few seconds.
func TestRunWithModel(t *testing.T) {
	d := Synthetic(t0, 5, 3)
	nc := model.DefaultNightlyConfig()
	nc.Train.TimeCap = 2 * time.Second
	nc.Train.MaxEpochs = 1
	nc.Train.MinRecords = 2000
	r, err := Run(context.Background(), d, Arm{Name: "rules+model", Model: true}, Options{Loc: time.UTC, Nightly: nc})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Model) != len(d.Rows) {
		t.Fatalf("recorded %d model verdicts for %d rows", len(r.Model), len(d.Rows))
	}
	var accepted int
	for _, tr := range r.Trainings {
		if tr.Report.Accepted {
			accepted++
		}
	}
	if len(r.Trainings) != 5 || accepted == 0 {
		t.Fatalf("trainings: %d run, %d accepted, want 5 run and some accepted: %+v", len(r.Trainings), accepted, r.Trainings)
	}
	s := Summarise(r, 0)
	if s.Days[len(s.Days)-1].Phase == "" {
		t.Error("phase not reported")
	}
	// Reusing the model's verdicts must reproduce the run exactly (tuning relies on it).
	r2, err := Run(context.Background(), d, Arm{Name: "again"}, Options{Loc: time.UTC, ModelVerdicts: r.Model})
	if err != nil {
		t.Fatal(err)
	}
	for i := range r.Out {
		if r.Out[i].Alert != r2.Out[i].Alert {
			t.Fatalf("row %d: alert %v, reused verdicts gave %v", i, r.Out[i].Alert, r2.Out[i].Alert)
		}
	}
}

func TestFilesRoundTrip(t *testing.T) {
	d := Synthetic(t0, 2, 4)
	p := filepath.Join(t.TempDir(), "m.jsonl.gz")
	if err := WriteMinutes(p, d); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Rows) != len(d.Rows) || !back.Installed.Equal(d.Installed) {
		t.Fatalf("rows %d/%d installed %v/%v", len(back.Rows), len(d.Rows), back.Installed, d.Installed)
	}
	if !reflect.DeepEqual(back.Rows[10], d.Rows[10]) {
		t.Errorf("row differs:\n%+v\n%+v", back.Rows[10], d.Rows[10])
	}
}
