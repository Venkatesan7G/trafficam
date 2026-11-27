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
	"github.com/Venkatesan7G/trafficam/internal/userlists"
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
	addr := testAddr(dir)
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

func TestAlertButtonsAndLists(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "a.db"), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hub := &alerts.Hub{St: st}
	lists := &Lists{Watch: userlists.File{Path: filepath.Join(dir, "watch.txt"), Kind: userlists.Watch},
		Ignore: userlists.File{Path: filepath.Join(dir, "ignore.txt"), Kind: userlists.Ignore}}
	srv := &Server{Hub: hub, Store: st, Actions: st, Lists: lists}
	addr := filepath.Join(dir, "api.sock")
	l, err := Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go srv.Serve(ctx, l)
	c := NewClient(addr)

	hub.Notify(score.Alert{Minute: event.Minute{Program: event.Program{Name: "updater", Path: "/opt/up/updater"}, Host: "cdn.example", Port: 443},
		Verdict: score.Verdict{Alert: true, Reasons: []string{"updater has never contacted cdn.example before"}}})
	hub.Notify(score.Alert{Minute: event.Minute{Program: event.Program{Name: "nc"}, Host: "evil.example", Port: 4444},
		Verdict: score.Verdict{Alert: true, Reasons: []string{"destination is on the known-bad list (evil.example)"}}})

	a, err := c.AlertOK(ctx, 1)
	if err != nil || a.State != store.AlertOK {
		t.Fatalf("ok: %+v %v", a, err)
	}
	if a, err = c.AlertMute(ctx, 1); err != nil || a.State != store.AlertMuted {
		t.Fatalf("mute: %+v %v", a, err)
	}
	ls, _ := c.Lists(ctx)
	if len(ls.Ignore) != 1 || ls.Ignore[0].Pattern != "cdn.example" || ls.Ignore[0].Program != "/opt/up/updater" {
		t.Fatalf("ignore list after mute: %+v", ls.Ignore)
	}
	// Known-bad alerts can't be muted through the ignore list.
	if _, err := c.AlertMute(ctx, 2); err == nil {
		t.Fatal("muted a known-bad alert")
	}
	if _, err := c.AlertOK(ctx, 99); err == nil {
		t.Fatal("OK on a missing alert")
	}
	// Watch add works; bad patterns are refused; ignore remove works.
	if ls, err = c.WatchAdd(ctx, RuleRequest{Pattern: "203.0.113.0/24"}); err != nil || len(ls.Watch) != 1 {
		t.Fatalf("watch add %+v %v", ls, err)
	}
	if _, err := c.WatchAdd(ctx, RuleRequest{Pattern: "bad pattern"}); err == nil {
		t.Fatal("bad pattern accepted")
	}
	if ls, err = c.IgnoreRemove(ctx, RuleRequest{Pattern: "cdn.example", Program: "/opt/up/updater"}); err != nil || len(ls.Ignore) != 0 {
		t.Fatalf("ignore remove %+v %v", ls, err)
	}
	// There is deliberately no way to add arbitrary ignore rules or remove watch rules.
	for _, p := range []string{"/v1/lists/ignore/add", "/v1/lists/watch/remove"} {
		if err := c.do(ctx, "POST", p, RuleRequest{Pattern: "x.example"}, nil); err == nil {
			t.Fatalf("%s should not exist", p)
		}
	}
	if lr, err := c.Learning(ctx); err != nil || lr.AlertsWeek != 2 {
		t.Fatalf("learning %+v %v", lr, err)
	}
}
