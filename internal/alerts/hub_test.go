package alerts

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

func TestWaitWakesOnNotify(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := &Hub{St: st}

	// Nothing yet: Wait times out with an empty list.
	if got, err := h.Wait(context.Background(), 0, 50*time.Millisecond); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	done := make(chan []store.Alert)
	go func() {
		got, _ := h.Wait(context.Background(), 0, 5*time.Second)
		done <- got
	}()
	time.Sleep(20 * time.Millisecond)
	h.Notify(score.Alert{
		Minute:  event.Minute{Start: time.Now(), Program: event.Program{Name: "nc", Path: "/usr/bin/nc"}, Host: "evil.example", Port: 4444},
		Verdict: score.Verdict{Score: 1, Alert: true, Reasons: []string{"on your watch list"}, Phase: "Watching"},
	})
	select {
	case got := <-done:
		if len(got) != 1 || got[0].Program != "nc" || got[0].ProgKey != "/usr/bin/nc" || got[0].Reasons[0] != "on your watch list" {
			t.Fatalf("got %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Wait did not wake")
	}
}
