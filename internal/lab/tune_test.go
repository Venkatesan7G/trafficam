package lab

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTune(t *testing.T) {
	d := Synthetic(t0, 10, 8)
	d, labels, attacks, err := Inject(d, InjectOptions{Seed: 3, Only: []string{"beacon-quiet", "dropper"}})
	if err != nil {
		t.Fatal(err)
	}
	// An early wave, inside the default program age.
	d, labels, more, err := Inject(d, InjectOptions{At: t0.Add(60 * time.Hour), MinHistory: 24 * time.Hour,
		Only: []string{"beacon-quiet"}, IDSuffix: "@60h", Prev: labels, Seed: 4})
	if err != nil {
		t.Fatal(err)
	}
	attacks = append(attacks, more...)
	grid := Grid([]time.Duration{24 * time.Hour, DefaultGrace}, []time.Duration{24 * time.Hour, DefaultAge}, []int{DefaultMaxHosts})
	rs, err := Tune(context.Background(), d, labels, attacks, grid, TuneOptions{Options: Options{Loc: time.UTC}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 4 {
		t.Fatalf("%d results for 4 settings", len(rs))
	}
	by := map[Setting]TuneResult{}
	for _, r := range rs {
		by[r.Setting] = r
	}
	def := by[Setting{DefaultGrace, DefaultAge, DefaultMaxHosts}]
	short := by[Setting{DefaultGrace, 24 * time.Hour, DefaultMaxHosts}]
	if !contains(def.Missed, "beacon-quiet@60h") {
		t.Errorf("defaults should miss the beacon 60 h after install (program not 72 h old yet): %+v", def)
	}
	if contains(short.Missed, "beacon-quiet@60h") {
		t.Errorf("a 24 h program age should catch it: %+v", short)
	}
	if Rank(rs)[0].Caught < def.Caught {
		t.Error("ranking put a worse catch rate first")
	}
	var sb strings.Builder
	WriteTuning(&sb, d, attacks, rs, false, 10)
	if !strings.Contains(sb.String(), "shipped default") {
		t.Error("report does not mark the default")
	}
	t.Log("\n" + sb.String())
}
