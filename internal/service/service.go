// Package service wires everything together and keeps it alive.
//
//	collector --emit--> [bounded queue] --> aggregator --> scorer --> store
//	                                                          \--> notifier
//
// Safety rules this package enforces (they exist so that trafficam can never
// harm the user's network or their machine):
//
//   - Collectors are passive; the service never gives them a way to affect
//     traffic, and emit() never blocks them (a full queue drops the flow).
//   - Every goroutine that runs foreign code (collector, scorer, notifier) is
//     wrapped in recover(). A panic is logged and counted; it does not take
//     the program down. A crashing collector is restarted with backoff.
//   - Queues are bounded, so a slow disk or slow model costs us some
//     observations, never unbounded memory.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/aggregate"
	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Config holds everything the service needs. Zero values get sane defaults.
type Config struct {
	Collector collector.Collector
	Scorer    score.Scorer   // default score.Nop{}
	Notifier  score.Notifier // default: log only
	Store     *store.Store   // required
	Log       *slog.Logger   // default slog.Default()

	QueueSize  int           // max flows waiting for the aggregator (default 8192)
	Grace      time.Duration // how late a flow may arrive and still count (default 1m)
	FlushEvery time.Duration // live mode: how often to close old minutes (default 10s)

	// Tasks are long-running background jobs (the model's nightly training
	// loop, database pruning). Each runs in its own supervised goroutine with
	// the same panic recovery and restart-with-backoff as the collector.
	Tasks []Task

	// Enrich, if set, adds ASN and country to rows from an offline table.
	Enrich aggregate.Enricher

	// OneShot ends the service when the collector finishes without error
	// (used for replay files). It also makes the queue lossless (emit waits
	// instead of dropping), since replay has no live traffic to protect. When false, a collector that returns is
	// treated as a failure and restarted, because live capture should never stop.
	OneShot bool

	// RestartBackoff is the first wait before restarting a failed collector;
	// it doubles up to MaxBackoff.
	RestartBackoff time.Duration
	MaxBackoff     time.Duration
}

// Task is a background job. Run must return when ctx is cancelled. If it
// returns early or panics it is restarted with backoff.
type Task struct {
	Name string
	Run  func(ctx context.Context) error
}

// Every wraps fn so it runs once now-ish (after `first`) and then every
// `interval`, until ctx is cancelled. Handy for pruning and similar jobs.
func Every(name string, first, interval time.Duration, fn func(ctx context.Context) error) Task {
	return Task{Name: name, Run: func(ctx context.Context) error {
		wait := first
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			if err := fn(ctx); err != nil {
				return err // supervisor logs it and restarts us
			}
			wait = interval
		}
	}}
}

// Stats are cheap counters, safe to read while running.
type Stats struct {
	Flows, Dropped, Rows, Alerts, Panics, Restarts, StoreErrors, ScoreErrors atomic.Uint64
}

type Service struct {
	cfg    Config
	log    *slog.Logger
	queue  chan event.Flow
	runCtx context.Context
	Stats  Stats
}

type logNotifier struct{ log *slog.Logger }

func (n logNotifier) Notify(a score.Alert) {
	n.log.Warn("ALERT", "program", a.Minute.Program.Name, "host", a.Minute.Host,
		"port", a.Minute.Port, "score", a.Verdict.Score, "reasons", a.Verdict.Reasons)
}

func New(cfg Config) (*Service, error) {
	if cfg.Collector == nil || cfg.Store == nil {
		return nil, fmt.Errorf("service: Collector and Store are required")
	}
	if cfg.Scorer == nil {
		cfg.Scorer = score.Nop{}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Notifier == nil {
		cfg.Notifier = logNotifier{cfg.Log}
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 8192
	}
	def(&cfg.Grace, time.Minute)
	def(&cfg.FlushEvery, 10*time.Second)
	def(&cfg.RestartBackoff, time.Second)
	def(&cfg.MaxBackoff, time.Minute)
	return &Service{cfg: cfg, log: cfg.Log, queue: make(chan event.Flow, cfg.QueueSize)}, nil
}

// Run blocks until ctx is cancelled (or, in OneShot mode, the collector ends),
// then flushes everything and returns.
func (s *Service) Run(ctx context.Context) error {
	s.runCtx = ctx
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // collector supervisor
		defer wg.Done()
		defer close(s.queue) // lets the processor drain and finish
		s.superviseCollector(ctx)
	}()
	// Background tasks stop when the main context ends or the pipeline is done.
	taskCtx, stopTasks := context.WithCancel(ctx)
	for _, t := range s.cfg.Tasks {
		wg.Add(1)
		go func(t Task) {
			defer wg.Done()
			s.superviseTask(taskCtx, t)
		}(t)
	}
	s.process(ctx) // returns once queue is closed and drained
	stopTasks()
	wg.Wait()
	return nil
}

// superviseCollector runs the collector, restarting it if it fails or panics.
func (s *Service) superviseCollector(ctx context.Context) {
	backoff := s.cfg.RestartBackoff
	for ctx.Err() == nil {
		started := time.Now()
		err := s.safely("collector "+s.cfg.Collector.Name(), func() error {
			return s.cfg.Collector.Run(ctx, s.emit)
		})
		if ctx.Err() != nil {
			return
		}
		if err == nil && s.cfg.OneShot {
			return
		}
		s.Stats.Restarts.Add(1)
		s.log.Error("collector stopped; restarting", "collector", s.cfg.Collector.Name(), "err", err, "in", backoff)
		if time.Since(started) > 5*time.Minute {
			backoff = s.cfg.RestartBackoff // it ran fine for a while; reset
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > s.cfg.MaxBackoff {
			backoff = s.cfg.MaxBackoff
		}
	}
}

// superviseTask runs a background task, restarting it if it fails or panics.
func (s *Service) superviseTask(ctx context.Context, t Task) {
	backoff := s.cfg.RestartBackoff
	for ctx.Err() == nil {
		err := s.safely("task "+t.Name, func() error { return t.Run(ctx) })
		if ctx.Err() != nil {
			return
		}
		s.Stats.Restarts.Add(1)
		s.log.Error("task stopped; restarting", "task", t.Name, "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > s.cfg.MaxBackoff {
			backoff = s.cfg.MaxBackoff
		}
	}
}

// emit is handed to collectors. It NEVER blocks: if the queue is full the
// flow is dropped and counted.
func (s *Service) emit(f event.Flow) {
	s.Stats.Flows.Add(1)
	if s.cfg.OneShot {
		// Offline replay must not lose flows, and there is no live network to
		// stall, so here (and only here) we wait for room in the queue.
		select {
		case s.queue <- f:
		case <-s.runCtx.Done():
		}
		return
	}
	select {
	case s.queue <- f:
	default:
		if s.Stats.Dropped.Add(1)%1000 == 1 {
			s.log.Warn("queue full, dropping flows", "dropped_total", s.Stats.Dropped.Load())
		}
	}
}

// process is the single goroutine that owns the aggregator.
func (s *Service) process(ctx context.Context) {
	agg := aggregate.New()
	agg.Enrich = s.cfg.Enrich
	tick := time.NewTicker(s.cfg.FlushEvery)
	defer tick.Stop()
	for {
		select {
		case f, ok := <-s.queue:
			if !ok {
				s.handle(agg.Drain()) // shutdown / end of replay: flush the rest
				return
			}
			agg.Add(f)
			s.handle(agg.CloseByEventTime(s.cfg.Grace))
		case <-tick.C:
			// Live safety net for quiet periods: close by wall-clock time.
			// Not used in OneShot (replay) mode where event time != wall time.
			if !s.cfg.OneShot {
				s.handle(agg.CloseOld(time.Now().Add(-s.cfg.Grace)))
			}
		}
	}
}

// handle scores a batch of closed rows, stores them, and notifies on alerts.
func (s *Service) handle(rows []event.Minute) {
	if len(rows) == 0 {
		return
	}
	s.Stats.Rows.Add(uint64(len(rows)))

	var verdicts []score.Verdict
	err := s.safely("scorer "+s.cfg.Scorer.Name(), func() error {
		var e error
		verdicts, e = s.cfg.Scorer.Score(context.Background(), rows)
		return e
	})
	if err == nil && len(verdicts) != len(rows) {
		err = fmt.Errorf("scorer returned %d verdicts for %d rows", len(verdicts), len(rows))
	}
	if err != nil {
		s.Stats.ScoreErrors.Add(1)
		s.log.Error("scoring failed; storing batch unscored", "err", err)
		verdicts = nil
	}

	out := make([]store.Scored, len(rows))
	for i, m := range rows {
		out[i].Minute = m
		if verdicts != nil {
			sc := verdicts[i].Score
			out[i].Score = &sc
			out[i].Alerted = verdicts[i].Alert
		}
	}
	if err := s.safely("store", func() error { return s.cfg.Store.Insert(out) }); err != nil {
		s.Stats.StoreErrors.Add(1)
		s.log.Error("store failed; batch lost", "err", err)
	}
	for i, v := range verdicts {
		if !v.Alert {
			continue
		}
		s.Stats.Alerts.Add(1)
		a := score.Alert{Minute: rows[i], Verdict: v}
		_ = s.safely("notifier", func() error { s.cfg.Notifier.Notify(a); return nil })
	}
}

// safely runs fn, converting a panic into an error (and counting it).
func (s *Service) safely(what string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.Stats.Panics.Add(1)
			s.log.Error("recovered from panic", "in", what, "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("%s panicked: %v", what, r)
		}
	}()
	return fn()
}
