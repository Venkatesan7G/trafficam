package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/notify"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

type fakeDesk struct {
	mu    sync.Mutex
	notes []notify.Note
}

func (f *fakeDesk) Name() string { return "fake" }
func (f *fakeDesk) Check() error { return nil }
func (f *fakeDesk) Show(n notify.Note) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notes = append(f.notes, n)
	return nil
}
func (f *fakeDesk) titles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var t []string
	for _, n := range f.notes {
		t = append(t, n.Title)
	}
	return t
}

// fakeAPI serves a fixed list of alerts; Wait hands out batches in order.
type fakeAPI struct {
	status  localapi.Status
	stored  []store.Alert
	batches [][]store.Alert
	waits   int
	cancel  func()
}

func (f *fakeAPI) Status(context.Context) (localapi.Status, error) { return f.status, nil }
func (f *fakeAPI) Alerts(_ context.Context, q store.AlertQuery) ([]store.Alert, error) {
	var out []store.Alert
	for _, a := range f.stored {
		if a.ID > q.AfterID && (q.State == "" || a.State == q.State) {
			out = append(out, a)
		}
	}
	return out, nil
}
func (f *fakeAPI) Wait(ctx context.Context, after int64) ([]store.Alert, error) {
	if f.waits >= len(f.batches) {
		f.cancel()
		return nil, ctx.Err()
	}
	f.waits++
	return f.batches[f.waits-1], nil
}

func al(id int64, host string) store.Alert {
	return store.Alert{ID: id, Program: "curl", Host: host, Proto: "tcp", Port: 443, State: store.AlertNew, Reasons: []string{"new"}}
}

func run(t *testing.T, api *fakeAPI, statePath string) *fakeDesk {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api.cancel = cancel
	if statePath == "" {
		statePath = filepath.Join(t.TempDir(), "state.json")
	}
	d := &fakeDesk{}
	a := New(Config{Desktop: d, StatePath: statePath, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Connect: func(context.Context) (API, error) { return api, nil }})
	a.Run(ctx)
	return d
}

func TestCatchUpThenLiveThenRateLimit(t *testing.T) {
	state := filepath.Join(t.TempDir(), "s.json")
	inst := time.Unix(1_700_000_000, 0)
	api := &fakeAPI{
		status: localapi.Status{InstalledAt: inst, LatestAlert: 2},
		stored: []store.Alert{al(1, "a.example"), al(2, "b.example")},
		batches: [][]store.Alert{
			{al(3, "c.example")},
			{al(4, "d.example"), al(5, "e.example"), al(6, "f.example")}, // over the 3/minute limit
		},
	}
	d := run(t, api, state)
	got := d.titles()
	want := []string{"curl contacted a.example", "curl contacted b.example", "curl contacted c.example"}
	if len(got) != 3 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %q", got)
	}

	// A restart does not repeat old alerts.
	api2 := &fakeAPI{status: localapi.Status{InstalledAt: inst, LatestAlert: 6}, stored: api.stored}
	if d := run(t, api2, state); len(d.titles()) != 0 {
		t.Fatalf("repeated after restart: %q", d.titles())
	}
	// A brand-new database (new install time) starts over.
	api3 := &fakeAPI{status: localapi.Status{InstalledAt: inst.Add(time.Hour), LatestAlert: 1}, stored: []store.Alert{al(1, "z.example")}}
	if d := run(t, api3, state); len(d.titles()) != 1 {
		t.Fatalf("new database: %q", d.titles())
	}
}

func TestBigCatchUpIsOneSummary(t *testing.T) {
	var many []store.Alert
	for i := int64(1); i <= 10; i++ {
		many = append(many, al(i, "x.example"))
	}
	d := run(t, &fakeAPI{status: localapi.Status{LatestAlert: 10}, stored: many}, "")
	if got := d.titles(); len(got) != 1 || got[0] != "trafficam: 10 new alerts" {
		t.Fatalf("got %q", got)
	}
}

func TestTamperShownOnConnect(t *testing.T) {
	d := run(t, &fakeAPI{status: localapi.Status{Tamper: "Key file replaced\n..."}}, "")
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.notes) != 1 || d.notes[0].Urgency != notify.Critical {
		t.Fatalf("got %+v", d.notes)
	}
}

func TestRetriesWhenServiceDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	tries := 0
	a := New(Config{Desktop: &fakeDesk{}, StatePath: filepath.Join(t.TempDir(), "s.json"), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RetryMax: 10 * time.Millisecond,
		Connect: func(context.Context) (API, error) { tries++; return nil, errors.New("down") }})
	start := time.Now()
	a.Run(ctx)
	if time.Since(start) > 2*time.Second || tries < 2 {
		t.Fatalf("tries=%d", tries)
	}
}
