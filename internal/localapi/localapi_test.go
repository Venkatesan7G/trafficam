package localapi

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/alerts"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

func startServer(t *testing.T) (*Client, *alerts.Hub, string) { return startServerIn(t, t.TempDir()) }

func startServerIn(t *testing.T, dir string) (*Client, *alerts.Hub, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "a.db"), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hub := &alerts.Hub{St: st}
	srv := &Server{Hub: hub, Store: st, MaxWait: 300 * time.Millisecond,
		Status: func() Status { return Status{Collector: "test", Flows: 7} }}
	addr := filepath.Join(dir, "api.sock")
	l, err := Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	return NewClient(addr), hub, addr
}

func TestStatusAlertsAndWait(t *testing.T) {
	c, hub, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := c.Status(ctx)
	if err != nil || st.Collector != "test" || st.Flows != 7 || st.LatestAlert != 0 {
		t.Fatalf("status %+v %v", st, err)
	}
	// Long-poll with nothing new returns empty after MaxWait.
	if got, err := c.Wait(ctx, 0); err != nil || len(got) != 0 {
		t.Fatalf("wait %v %v", got, err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		hub.Notify(score.Alert{Minute: event.Minute{Program: event.Program{Name: "nc"}, Host: "c2.example", Port: 4444},
			Verdict: score.Verdict{Score: 1, Alert: true, Reasons: []string{"watch list"}}})
	}()
	var got []store.Alert
	for i := 0; i < 5 && len(got) == 0; i++ {
		if got, err = c.Wait(ctx, 0); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 1 || got[0].Host != "c2.example" {
		t.Fatalf("wait got %+v", got)
	}
	st, _ = c.Status(ctx)
	if st.Unread != 1 || st.LatestAlert != got[0].ID {
		t.Fatalf("status after alert %+v", st)
	}
	if l, err := c.Alerts(ctx, store.AlertQuery{State: store.AlertNew}); err != nil || len(l) != 1 {
		t.Fatalf("alerts %v %v", l, err)
	}
}

func TestSecondListenerRefused(t *testing.T) {
	_, _, addr := startServer(t)
	if _, err := Listen(addr); err == nil {
		t.Fatal("a second service took over a live socket")
	}
}
