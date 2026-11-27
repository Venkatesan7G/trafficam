// Package alerts keeps the alerts the user should see and tells whoever is
// listening (the desktop agent in the user's session) the moment a new one
// arrives.
//
// Hub implements score.Notifier, so the service hands it every alert. It
// stores the alert (so nothing is lost if no one is logged in, or the agent is
// not running) and wakes any waiting listeners. It never blocks the service
// for longer than one small database insert.
package alerts

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/score"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Store is the part of store.Store the hub needs.
type Store interface {
	AlertAdd(store.Alert) (store.Alert, error)
	Alerts(store.AlertQuery) ([]store.Alert, error)
}

// Hub stores alerts and wakes listeners.
type Hub struct {
	St  Store
	Log *slog.Logger     // optional; every alert is also logged
	Now func() time.Time // for tests

	mu     sync.Mutex
	wake   chan struct{} // closed and replaced when a new alert arrives
	lastID int64
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Hub) signal(id int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if id > h.lastID {
		h.lastID = id
	}
	if h.wake != nil {
		close(h.wake)
		h.wake = nil
	}
}

func (h *Hub) waitChan() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wake == nil {
		h.wake = make(chan struct{})
	}
	return h.wake
}

// Notify implements score.Notifier.
func (h *Hub) Notify(a score.Alert) {
	m, v := a.Minute, a.Verdict
	if h.Log != nil {
		h.Log.Warn("ALERT", "program", m.Program.Name, "host", m.Host, "port", m.Port, "score", v.Score, "reasons", v.Reasons)
	}
	stored, err := h.St.AlertAdd(store.Alert{
		At: h.now().UTC(), Start: m.Start, ProgKey: m.Program.Key(), Program: m.Program.Name, Path: m.Program.Path,
		Service: m.Program.Service, Proto: string(m.Proto), Dir: string(m.Dir), Host: m.Host, RemoteIP: m.RemoteIP,
		Port: m.Port, ASN: m.ASN, Country: m.Country, Score: v.Score, Reasons: v.Reasons, Phase: v.Phase,
	})
	if err != nil {
		if h.Log != nil {
			h.Log.Error("could not store alert (it was logged above)", "err", err)
		}
		return
	}
	h.signal(stored.ID)
}

// Wait returns alerts with ID > after. If there are none yet it waits until
// one arrives, ctx ends, or maxWait passes (then it returns an empty list).
func (h *Hub) Wait(ctx context.Context, after int64, maxWait time.Duration) ([]store.Alert, error) {
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	for {
		ch := h.waitChan() // take the channel BEFORE reading, so no alert slips between
		got, err := h.St.Alerts(store.AlertQuery{AfterID: after, Limit: 100})
		if err != nil || len(got) > 0 {
			return got, err
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, nil
		case <-timer.C:
			return nil, nil
		}
	}
}
