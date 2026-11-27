package lab

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/model"
)

func TestInjectLabelsEveryAttackRow(t *testing.T) {
	d := Synthetic(t0, 10, 5)
	inj, labels, attacks, err := Inject(d, InjectOptions{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(inj.Rows) != len(labels) || len(d.Rows) == len(inj.Rows) {
		t.Fatalf("rows %d labels %d (clean %d)", len(inj.Rows), len(labels), len(d.Rows))
	}
	n := map[string]int{}
	for i, l := range labels {
		if i > 0 && inj.Rows[i].Start.Before(inj.Rows[i-1].Start) {
			t.Fatal("rows not in time order after injection")
		}
		n[l]++
	}
	for _, a := range attacks {
		if n[a.ID] != a.Rows || a.Rows == 0 {
			t.Errorf("%s: %d labelled rows, attack says %d", a.ID, n[a.ID], a.Rows)
		}
	}
	if n[""] != len(d.Rows) {
		t.Errorf("%d clean rows, want %d", n[""], len(d.Rows))
	}
}

func TestInjectNeedsHistory(t *testing.T) {
	if _, _, _, err := Inject(Synthetic(t0, 3, 1), InjectOptions{}); err == nil {
		t.Error("planting into a 3-day recording should be refused")
	}
}

// Rules alone catch the easy attacks and miss the ones marked Hard: this pins
// down what the rules can and cannot do, so a change in either shows up.
func TestRulesOnlyScorecard(t *testing.T) {
	d, labels, attacks, err := Inject(Synthetic(t0, 10, 6), InjectOptions{Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), d, Arm{Name: "rules"}, Options{Loc: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	sc := Score(r, labels, attacks, 0)
	for i, a := range attacks {
		o := sc.Outcomes[i]
		if a.Hard && o.Caught {
			t.Errorf("%s: rules caught a 'hard' attack (%v); update Hard or the rules changed", a.ID, o.Kinds)
		}
		if !a.Hard && !o.Caught {
			t.Errorf("%s: rules missed it", a.ID)
		}
	}
	if sc.FalsePer > 1 {
		t.Errorf("%.2f false alarms a day on the fake PC with rules only", sc.FalsePer)
	}
	var sb strings.Builder
	WriteComparison(&sb, d, attacks, []*Scorecard{sc})
	t.Log("\n" + sb.String())
}

func TestApplyLabels(t *testing.T) {
	d := Synthetic(t0, 2, 7)
	p := filepath.Join(t.TempDir(), "labels.jsonl")
	day2 := t0.Add(24 * time.Hour)
	os.WriteFile(p, []byte(`# comment
{"id":"mail-burst","kind":"exfil","program":"MAIL-client","host":"smtp","start":"`+day2.Add(10*time.Hour).Format(time.RFC3339)+`","end":"`+day2.Add(11*time.Hour).Format(time.RFC3339)+`"}
`), 0o600)
	labels, attacks, err := ApplyLabels(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(attacks) != 1 || attacks[0].Rows == 0 {
		t.Fatalf("attacks %+v", attacks)
	}
	for i, l := range labels {
		if l != "" && (d.Rows[i].Host != "smtp.mail.example" || d.Rows[i].Start.Before(day2.Add(10*time.Hour))) {
			t.Fatalf("wrong row labelled: %+v", d.Rows[i])
		}
	}
	os.WriteFile(p, []byte(`{"id":"x","program":"nosuch","start":"`+day2.Format(time.RFC3339)+`","end":"`+day2.Add(time.Hour).Format(time.RFC3339)+`"}`), 0o600)
	if _, _, err := ApplyLabels(p, d); err == nil {
		t.Error("a label matching nothing should be an error")
	}
}

// The full comparison with the model takes about half a minute, so it only
// runs when asked: TRAFFICAM_LAB_LONG=1 go test -run ModelScorecard ./internal/lab
func TestModelScorecard(t *testing.T) {
	if os.Getenv("TRAFFICAM_LAB_LONG") == "" {
		t.Skip("set TRAFFICAM_LAB_LONG=1 to run (about 30 s)")
	}
	d, labels, attacks, err := Inject(Synthetic(t0, 14, 1), InjectOptions{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	nc := model.DefaultNightlyConfig()
	nc.Train.TimeCap = 10 * time.Second
	var cards []*Scorecard
	for _, a := range []Arm{{Name: "rules"}, {Name: "rules+model", Model: true}} {
		r, err := Run(context.Background(), d, a, Options{Loc: time.UTC, Nightly: nc})
		if err != nil {
			t.Fatal(err)
		}
		cards = append(cards, Score(r, labels, attacks, 0))
	}
	var sb strings.Builder
	WriteComparison(&sb, d, attacks, cards)
	WriteFalseAlarmSources(&sb, cards, false)
	t.Log("\n" + sb.String())
	if cards[1].Caught < cards[0].Caught {
		t.Errorf("the model arm caught fewer attacks (%d) than rules alone (%d)", cards[1].Caught, cards[0].Caught)
	}
}
