package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/alerts"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// AlertStore is the part of store.Store the API needs.
type AlertStore interface {
	Alerts(store.AlertQuery) ([]store.Alert, error)
	AlertCounts() (map[store.AlertState]int, error)
}

// Server answers the local API.
type Server struct {
	Hub    *alerts.Hub
	Store  AlertStore
	Status func() Status // filled in by the service owner
	// Actions and Lists enable the alert buttons and list editing; nil = off.
	Actions ActionStore
	Lists   *Lists
	Log     *slog.Logger

	// MaxWait caps a long-poll (default 25 s, below common client timeouts).
	MaxWait time.Duration

	mux *http.ServeMux
}

// Handler returns the HTTP handler (also used directly in tests).
func (s *Server) Handler() http.Handler {
	if s.mux != nil {
		return s.mux
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/status", s.status)
	m.HandleFunc("GET /v1/alerts", s.list)
	m.HandleFunc("GET /v1/alerts/wait", s.wait)
	s.registerActions(m)
	s.mux = m
	return m
}

// Serve answers on l until ctx ends.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      s.maxWait() + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		hs.Shutdown(sh)
	}()
	err := hs.Serve(l)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) maxWait() time.Duration {
	if s.MaxWait <= 0 {
		return 25 * time.Second
	}
	return s.MaxWait
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st := Status{Now: time.Now().UTC()}
	if s.Status != nil {
		st = s.Status()
	}
	if c, err := s.Store.AlertCounts(); err == nil {
		st.Unread = c[store.AlertNew]
	}
	if last, err := s.Store.Alerts(store.AlertQuery{Limit: 1, Newest: true}); err == nil && len(last) == 1 {
		st.LatestAlert = last[0].ID
	}
	writeJSON(w, st)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	got, err := s.Store.Alerts(q)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, AlertList{Alerts: nonNil(got)})
}

func (s *Server) wait(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	got, err := s.Hub.Wait(r.Context(), q.AfterID, s.maxWait())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, AlertList{Alerts: nonNil(got)})
}

func parseQuery(r *http.Request) (store.AlertQuery, error) {
	var q store.AlertQuery
	v := r.URL.Query()
	var err error
	if a := v.Get("after"); a != "" {
		if q.AfterID, err = strconv.ParseInt(a, 10, 64); err != nil {
			return q, errors.New("bad after")
		}
	}
	if l := v.Get("limit"); l != "" {
		if q.Limit, err = strconv.Atoi(l); err != nil {
			return q, errors.New("bad limit")
		}
	}
	if sec := v.Get("since"); sec != "" {
		n, err := strconv.ParseInt(sec, 10, 64)
		if err != nil {
			return q, errors.New("bad since")
		}
		q.Since = time.Unix(n, 0)
	}
	switch st := store.AlertState(v.Get("state")); st {
	case "", store.AlertNew, store.AlertOK, store.AlertMuted:
		q.State = st
	default:
		return q, errors.New("bad state")
	}
	q.Newest = v.Get("newest") == "1"
	return q, nil
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if s.Log != nil {
		s.Log.Error("local API", "err", err)
	}
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func nonNil(a []store.Alert) []store.Alert {
	if a == nil {
		return []store.Alert{}
	}
	return a
}
