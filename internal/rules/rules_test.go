package rules

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/baseline"
	"github.com/Venkatesan7G/trafficam/internal/blocklist"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

func newStore(t *testing.T) *store.Store {
	s, err := store.Open(filepath.Join(t.TempDir(), "t.db"), bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func row(at time.Time, prog, host string) event.Minute {
	return event.Minute{V: event.SchemaVersion, Start: at.Truncate(time.Minute),
		Program: event.Program{Name: prog, Path: "/bin/" + prog}, Proto: event.TCP, Dir: event.Outbound, Host: host, Port: 443, Flows: 1}
}

func list(t *testing.T, lines ...string) *blocklist.List {
	l := blocklist.New()
	for _, ln := range lines {
		if err := l.Add(ln); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func TestBlocklistAlwaysAlertsAndIgnoreCannotSilenceIt(t *testing.T) {
	st := newStore(t)
	s, _ := NewScorer(Config{Baseline: &baseline.Tracker{B: st}, Blocklist: list(t, "evil.example"), Ignore: list(t, "evil.example", "ok.example")}, nil)
	now := time.Now()
	v, err := s.Score(context.Background(), []event.Minute{row(now, "a", "x.evil.example"), row(now, "a", "ok.example")})
	if err != nil || !v[0].Alert || v[0].Score != 1 || v[1].Alert {
		t.Fatalf("err=%v v=%+v", err, v)
	}
}

func TestNoveltyRules(t *testing.T) {
	st := newStore(t)
	// Pretend the install is 10 days old and the clock has moved on.
	base := time.Now().Add(-10 * 24 * time.Hour)
	clock := base
	s, _ := NewScorer(Config{Baseline: &baseline.Tracker{B: st}, Ignore: list(t, "muted.example"), Now: func() time.Time { return clock }}, nil)
	ctx := context.Background()
	at, _ := st.InstalledAt()
	clock = at // install age 0: inside the grace window
	v, _ := s.Score(ctx, []event.Minute{row(clock, "chronyd", "pool.ntp.org")})
	if v[0].Alert {
		t.Fatal("alerted during install grace window")
	}
	// 4 days later chronyd has history; a brand-new program should alert once.
	for d := 1; d <= 4; d++ {
		clock = at.Add(time.Duration(d) * 24 * time.Hour)
		s.Score(ctx, []event.Minute{row(clock, "chronyd", "pool.ntp.org")})
	}
	v, _ = s.Score(ctx, []event.Minute{row(clock, "newtool", "a.example"), row(clock.Add(time.Minute), "newtool", "b.example")})
	if !v[0].Alert || v[1].Alert {
		t.Fatalf("new program: want alert on first row only, got %+v", v)
	}
	// Settled low-fan-out program contacting a new host alerts; a known host and an ignored host do not.
	v, _ = s.Score(ctx, []event.Minute{row(clock, "chronyd", "c2.example"), row(clock, "chronyd", "pool.ntp.org"), row(clock, "chronyd", "muted.example")})
	if !v[0].Alert || v[1].Alert || v[2].Alert {
		t.Fatalf("new host: got %+v", v)
	}
	// The same host the next day is no longer "new" (it has been counted).
	clock = clock.Add(time.Hour)
	v, _ = s.Score(ctx, []event.Minute{row(clock, "chronyd", "c2.example")})
	if v[0].Alert {
		t.Fatal("alerted twice for the same destination")
	}
}

func TestModelFailureStillGivesRuleAnswers(t *testing.T) {
	st := newStore(t)
	var got []error
	s, _ := NewScorer(Config{Baseline: &baseline.Tracker{B: st}, Blocklist: list(t, "198.51.100.0/24")}, failing{})
	s.OnError = func(e error) { got = append(got, e) }
	m := row(time.Now(), "a", "198.51.100.9")
	v, err := s.Score(context.Background(), []event.Minute{m})
	if err != nil || !v[0].Alert || len(got) == 0 {
		t.Fatalf("err=%v v=%+v reported=%d", err, v, len(got))
	}
}
