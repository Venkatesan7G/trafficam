package localapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/store"
	"github.com/Venkatesan7G/trafficam/internal/userlists"
)

// What the desktop may change, and why.
//
// The desktop user (and so any program running as that user, including
// malware) can freely make trafficam LOUDER: mark alerts as seen, add to the
// watch list, take rules off the ignore list. It can make trafficam QUIETER
// only for one alert that was actually raised and shown ("don't show again"
// adds exactly that program + destination to the ignore list). Wider changes
// that silence alerts (adding arbitrary ignore rules, removing watch rules)
// need an administrator: "trafficam lists ..." in an admin terminal.

// Lists gives the API the user's list files.
type Lists struct {
	Watch, Ignore userlists.File
}

// Learning is how much the watcher has learned so far.
type Learning struct {
	Programs     int `json:"programs"`     // programs seen using the network
	Destinations int `json:"destinations"` // (program, destination) pairs known
	AlertsWeek   int `json:"alerts_week"`  // alerts in the last 7 days
}

// ListsReply is the reply to GET /v1/lists.
type ListsReply struct {
	Watch  []userlists.Entry `json:"watch"`
	Ignore []userlists.Entry `json:"ignore"`
}

// RuleRequest is the body of the list-changing calls.
type RuleRequest struct {
	Pattern string `json:"pattern"`
	Program string `json:"program,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ActionStore is the part of store.Store the actions need.
type ActionStore interface {
	AlertGet(id int64) (store.Alert, error)
	AlertSetState(id int64, st store.AlertState, at time.Time) error
	SeenStats() (programs, pairs int, err error)
	AlertCountSince(t time.Time) (int, error)
}

func (s *Server) registerActions(m *http.ServeMux) {
	m.HandleFunc("POST /v1/alerts/{id}/ok", s.alertOK)
	m.HandleFunc("POST /v1/alerts/{id}/mute", s.alertMute)
	m.HandleFunc("GET /v1/lists", s.lists)
	m.HandleFunc("POST /v1/lists/watch/add", s.watchAdd)
	m.HandleFunc("POST /v1/lists/ignore/remove", s.ignoreRemove)
	m.HandleFunc("GET /v1/learning", s.learning)
}

func (s *Server) alertID(w http.ResponseWriter, r *http.Request) (store.Alert, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || s.Actions == nil {
		http.Error(w, "bad alert id", http.StatusBadRequest)
		return store.Alert{}, false
	}
	a, err := s.Actions.AlertGet(id)
	if err != nil {
		http.Error(w, "no such alert", http.StatusNotFound)
		return a, false
	}
	return a, true
}

func (s *Server) alertOK(w http.ResponseWriter, r *http.Request) {
	a, ok := s.alertID(w, r)
	if !ok {
		return
	}
	if a.State == store.AlertNew {
		if err := s.Actions.AlertSetState(a.ID, store.AlertOK, time.Now()); err != nil {
			s.fail(w, err)
			return
		}
	}
	a, _ = s.Actions.AlertGet(a.ID)
	writeJSON(w, a)
}

// alertMute is "don't show again": the alert's own program and destination
// go on the ignore list. Known-bad and watch-list alerts cannot be muted
// this way, because the ignore list does not silence them anyway; the user
// is told to edit the watch list (or the known-bad snapshot) instead.
func (s *Server) alertMute(w http.ResponseWriter, r *http.Request) {
	a, ok := s.alertID(w, r)
	if !ok {
		return
	}
	if s.Lists == nil {
		http.Error(w, "lists are not available", http.StatusServiceUnavailable)
		return
	}
	for _, r := range a.Reasons { // reason texts from internal/rules
		if strings.Contains(r, "known-bad list") || strings.Contains(r, "your watch list") {
			http.Error(w, "This alert comes from your watch list or the known-bad list, and the ignore list can't silence those. "+
				"Press OK to clear it. To stop it for good, take the rule off your watch list: "+
				"trafficam lists remove watch ... in an administrator terminal.", http.StatusConflict)
			return
		}
	}
	pattern := a.Host
	if pattern == "" {
		pattern = a.RemoteIP
	}
	prog := a.Path
	if prog == "" {
		prog = a.Program
	}
	if _, err := userlists.Validate(pattern, prog); err != nil {
		// e.g. a program path with spaces: fall back to the short name.
		prog = a.Program
	}
	note := fmt.Sprintf("muted from alert %d on %s", a.ID, time.Now().Format("2006-01-02"))
	if _, err := s.Lists.Ignore.Add(pattern, prog, note); err != nil {
		http.Error(w, "could not add to the ignore list: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := s.Actions.AlertSetState(a.ID, store.AlertMuted, time.Now()); err != nil {
		s.fail(w, err)
		return
	}
	if s.Log != nil {
		s.Log.Info("alert muted from the desktop", "id", a.ID, "program", prog, "host", pattern)
	}
	a, _ = s.Actions.AlertGet(a.ID)
	writeJSON(w, a)
}

func (s *Server) lists(w http.ResponseWriter, r *http.Request) {
	if s.Lists == nil {
		writeJSON(w, ListsReply{Watch: []userlists.Entry{}, Ignore: []userlists.Entry{}})
		return
	}
	var rep ListsReply
	var err error
	if rep.Watch, err = s.Lists.Watch.Entries(); err == nil {
		rep.Ignore, err = s.Lists.Ignore.Entries()
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if rep.Watch == nil {
		rep.Watch = []userlists.Entry{}
	}
	if rep.Ignore == nil {
		rep.Ignore = []userlists.Entry{}
	}
	writeJSON(w, rep)
}

func readRule(w http.ResponseWriter, r *http.Request) (RuleRequest, bool) {
	var req RuleRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (s *Server) watchAdd(w http.ResponseWriter, r *http.Request) {
	req, ok := readRule(w, r)
	if !ok || s.Lists == nil {
		if ok {
			http.Error(w, "lists are not available", http.StatusServiceUnavailable)
		}
		return
	}
	if _, err := s.Lists.Watch.Add(req.Pattern, req.Program, req.Note); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.lists(w, r)
}

func (s *Server) ignoreRemove(w http.ResponseWriter, r *http.Request) {
	req, ok := readRule(w, r)
	if !ok || s.Lists == nil {
		if ok {
			http.Error(w, "lists are not available", http.StatusServiceUnavailable)
		}
		return
	}
	n, err := s.Lists.Ignore.Remove(req.Pattern, req.Program)
	if err != nil {
		s.fail(w, err)
		return
	}
	if n == 0 {
		http.Error(w, "that rule is not on the ignore list", http.StatusNotFound)
		return
	}
	s.lists(w, r)
}

func (s *Server) learning(w http.ResponseWriter, r *http.Request) {
	var l Learning
	if s.Actions != nil {
		var err error
		if l.Programs, l.Destinations, err = s.Actions.SeenStats(); err != nil {
			s.fail(w, err)
			return
		}
	}
	if s.Actions != nil {
		if n, err := s.Actions.AlertCountSince(time.Now().AddDate(0, 0, -7)); err == nil {
			l.AlertsWeek = n
		}
	}
	writeJSON(w, l)
}

var errStatus = errors.New("trafficam service")

// post sends a JSON body (or none) and decodes the reply into out.
func (c *Client) post(r *http.Request, out any) error {
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &HTTPError{Code: resp.StatusCode, Msg: string(b)}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// HTTPError is a refusal from the service, with its reason.
type HTTPError struct {
	Code int
	Msg  string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%v: %d: %s", errStatus, e.Code, e.Msg) }
