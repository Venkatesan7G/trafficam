package ramp

import (
	"testing"
	"time"
)

func TestAt(t *testing.T) {
	d := 24 * time.Hour
	cases := []struct {
		age   time.Duration
		stage string
		next  int
	}{{0, "Listening", 4}, {3*d + 23*time.Hour, "Listening", 1}, {4 * d, "Settling in", 7}, {11 * d, "Watching", 19}, {45 * d, "Guarding", 0}}
	for _, c := range cases {
		p := At(c.age)
		if p.Stage != c.stage || p.NextIn != c.next {
			t.Errorf("%v: got %+v", c.age, p)
		}
	}
	if At(15*d).Percent != 50 || At(90*d).Percent != 100 {
		t.Error("percent")
	}
}
