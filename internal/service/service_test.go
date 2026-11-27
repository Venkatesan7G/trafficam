package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

func newStore(t *testing.T) *store.Store {
	s, err := store.Open(filepath.Join(t.TempDir(), "t.db"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(discard{}, nil)) }

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

type alertOnHost struct{ host string }

func (alertOnHost) Name() string { return "test" }
func (a alertOnHost) Score(_ context.Context, b []event.Minute) ([]score.Verdict, error) {
	v := make([]score.Verdict, len(b))
	for i, m := range b {
		if m.Host == a.host {
			v[i] = score.Verdict{Score: 1, Alert: true, Reasons: []string{"new host"}}
		}
	}
	return v, nil
}

type countNotifier struct{ n atomic.Int32 }

func (c *countNotifier) Notify(score.Alert) { c.n.Add(1) }

func synth(n, surprise int) *collector.Synthetic {
	return &collector.Synthetic{Start: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC), Step: 5 * time.Second, Count: n, Surprise: surprise}
}

func TestEndToEndAlertAndStore(t *testing.T) {
	st, notes := newStore(t), &countNotifier{}
	s, _ := New(Config{Collector: synth(200, 150), Store: st, OneShot: true, Scorer: alertOnHost{"evil-c2.example.net"}, Notifier: notes, Log: quiet()})
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notes.n.Load() != 1 || s.Stats.Alerts.Load() != 1 {
		t.Fatalf("want 1 alert, got %d", notes.n.Load())
	}
	rows, _ := st.Since(time.Unix(0, 0))
	if len(rows) == 0 || s.Stats.Dropped.Load() != 0 {
		t.Fatalf("rows=%d dropped=%d", len(rows), s.Stats.Dropped.Load())
	}
}

type panicScorer struct{}

func (panicScorer) Name() string { return "boom" }
func (panicScorer) Score(context.Context, []event.Minute) ([]score.Verdict, error) {
	panic("model exploded")
}

func TestScorerPanicDoesNotStopPipeline(t *testing.T) {
	st := newStore(t)
	s, _ := New(Config{Collector: synth(100, 0), Store: st, OneShot: true, Scorer: panicScorer{}, Log: quiet()})
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.Since(time.Unix(0, 0))
	if s.Stats.Panics.Load() == 0 || len(rows) == 0 || rows[0].Score != nil {
		t.Fatalf("panics=%d rows=%d (rows must be stored unscored)", s.Stats.Panics.Load(), len(rows))
	}
}

// flaky panics on its first run, then behaves.
type flaky struct{ runs atomic.Int32 }

func (*flaky) Name() string { return "flaky" }
func (f *flaky) Run(ctx context.Context, emit func(event.Flow)) error {
	if f.runs.Add(1) == 1 {
		panic("collector crashed")
	}
	if f.runs.Load() == 2 {
		return errors.New("transient failure")
	}
	return synth(30, 0).Run(ctx, emit)
}

func TestCollectorCrashIsRestarted(t *testing.T) {
	st := newStore(t)
	s, _ := New(Config{Collector: &flaky{}, Store: st, OneShot: true, RestartBackoff: time.Millisecond, Log: quiet()})
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Stats.Restarts.Load() != 2 || s.Stats.Panics.Load() != 1 || s.Stats.Flows.Load() != 30 {
		t.Fatalf("restarts=%d panics=%d flows=%d", s.Stats.Restarts.Load(), s.Stats.Panics.Load(), s.Stats.Flows.Load())
	}
}

// burst emits far more flows than the queue holds while the consumer is busy.
func TestLiveQueueDropsInsteadOfBlocking(t *testing.T) {
	s, _ := New(Config{Collector: synth(1, 0), Store: newStore(t), QueueSize: 4, Log: quiet()})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ { // nobody is draining the queue
			s.emit(event.Flow{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit blocked: capture could stall")
	}
	if s.Stats.Dropped.Load() != 996 {
		t.Fatalf("dropped=%d", s.Stats.Dropped.Load())
	}
}

func TestTasksRunAreRestartedAndStopWithPipeline(t *testing.T) {
	var runs, ticks atomic.Int32
	tasks := []Task{
		{Name: "crashy", Run: func(ctx context.Context) error {
			if runs.Add(1) == 1 {
				panic("task crashed")
			}
			<-ctx.Done()
			return nil
		}},
		Every("tick", 0, time.Millisecond, func(context.Context) error { ticks.Add(1); return nil }),
	}
	s, _ := New(Config{Collector: synth(2000, 0), Store: newStore(t), OneShot: true, Tasks: tasks, RestartBackoff: time.Millisecond, Log: quiet()})
	if err := s.Run(context.Background()); err != nil { // must return: tasks are stopped at the end
		t.Fatal(err)
	}
	if runs.Load() != 2 || s.Stats.Panics.Load() != 1 || ticks.Load() == 0 {
		t.Fatalf("runs=%d panics=%d ticks=%d", runs.Load(), s.Stats.Panics.Load(), ticks.Load())
	}
}
