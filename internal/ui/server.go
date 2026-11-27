// Package ui is the trafficam window: a small page served by the desktop
// agent on 127.0.0.1 and opened in the user's own browser. It shows the
// learning progress (Listening, Settling in, Watching, Guarding), the
// alerts with "OK" and "Don't show again", the watch and ignore lists and
// the self-check.
//
// It is built so that nothing else can use it:
//
//   - It listens on 127.0.0.1 only, on a random port, and only while the
//     agent runs. Other computers cannot reach it.
//   - Other local users and web pages cannot use it either. A browser gets in
//     only with a one-time ticket (in the link from a notification or from
//     "trafficam ui"), which is swapped for a random session cookie
//     (HttpOnly, SameSite=Strict). A ticket that ends up in browser history
//     is useless because it has already been used.
//   - Requests whose Host header is not 127.0.0.1:<port> are refused (this
//     defeats DNS-rebinding tricks), changes need a custom header that other
//     sites' pages cannot send, and a strict Content-Security-Policy allows
//     nothing but the page's own files. No external fonts, scripts or images:
//     it works fully offline.
//   - The page itself holds no secrets and can do only what the local API
//     allows the desktop to do (see localapi/actions.go).
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/selfcheck"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

//go:embed static
var staticFS embed.FS

// Backend is what the window needs from the watcher service.
type Backend interface {
	Status(ctx context.Context) (localapi.Status, error)
	Alerts(ctx context.Context, q store.AlertQuery) ([]store.Alert, error)
	AlertOK(ctx context.Context, id int64) (store.Alert, error)
	AlertMute(ctx context.Context, id int64) (store.Alert, error)
	Lists(ctx context.Context) (localapi.ListsReply, error)
	WatchAdd(ctx context.Context, r localapi.RuleRequest) (localapi.ListsReply, error)
	IgnoreRemove(ctx context.Context, r localapi.RuleRequest) (localapi.ListsReply, error)
	Learning(ctx context.Context) (localapi.Learning, error)
}

// Server is the trafficam window.
type Server struct {
	Connect func(ctx context.Context) (Backend, error)
	Check   func(ctx context.Context) []selfcheck.Result
	Log     *slog.Logger

	TicketTTL  time.Duration // [12h] how long an unused ticket stays valid
	SessionTTL time.Duration // [12h]

	mu       sync.Mutex
	addr     string // 127.0.0.1:port once listening
	launcher string // secret that lets "trafficam ui" ask for a ticket
	tickets  map[string]time.Time
	sessions map[string]time.Time
	hs       *http.Server
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS random source never fails in practice
	}
	return hex.EncodeToString(b)
}

// Listen opens 127.0.0.1 on a random free port. Call Serve next.
func (s *Server) Listen() (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.addr = l.Addr().String()
	s.launcher = randHex(32)
	s.tickets, s.sessions = map[string]time.Time{}, map[string]time.Time{}
	s.mu.Unlock()
	return l, nil
}

// Addr is 127.0.0.1:port.
func (s *Server) Addr() string { s.mu.Lock(); defer s.mu.Unlock(); return s.addr }

// LauncherSecret is written (readable only by this user) next to the address
// so "trafficam ui" can ask the running agent for a ticket.
func (s *Server) LauncherSecret() string { s.mu.Lock(); defer s.mu.Unlock(); return s.launcher }

// TicketURL returns a fresh one-time link that opens the window.
func (s *Server) TicketURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addr == "" {
		return ""
	}
	t := randHex(24)
	s.tickets[t] = time.Now().Add(s.ttl(s.TicketTTL))
	s.gcLocked()
	return "http://" + s.addr + "/?t=" + t
}

func (s *Server) ttl(d time.Duration) time.Duration {
	if d <= 0 {
		return 12 * time.Hour
	}
	return d
}

func (s *Server) gcLocked() {
	now := time.Now()
	for k, exp := range s.tickets {
		if now.After(exp) {
			delete(s.tickets, k)
		}
	}
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	// A flood of notifications must not grow memory without bound.
	for k := range s.tickets {
		if len(s.tickets) <= 200 {
			break
		}
		delete(s.tickets, k)
	}
}

// Serve answers on l until ctx ends.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.hs = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.hs.Shutdown(c)
	}()
	err := s.hs.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler is the whole window, with the security checks in front.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(static)
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if t := r.URL.Query().Get("t"); t != "" {
			s.login(w, r, t)
			return
		}
		if !s.hasSession(r) {
			denied(w)
			return
		}
		files.ServeHTTP(w, r)
	})
	m.HandleFunc("GET /static/{file}", func(w http.ResponseWriter, r *http.Request) {
		if !s.hasSession(r) {
			denied(w)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + r.PathValue("file")
		files.ServeHTTP(w, r2)
	})
	m.HandleFunc("POST /launch", s.launch)
	api := func(pattern string, h func(ctx context.Context, b Backend, r *http.Request) (any, error)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.hasSession(r) {
				http.Error(w, "not signed in", http.StatusForbidden)
				return
			}
			if r.Method == http.MethodPost && !sameOriginPost(r, s.Addr()) {
				http.Error(w, "refused", http.StatusForbidden)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			var b Backend
			var err error
			if s.Connect != nil {
				b, err = s.Connect(ctx)
			} else {
				err = errors.New("no service")
			}
			if err != nil && pattern != "GET /api/check" {
				http.Error(w, "the trafficam service is not reachable", http.StatusBadGateway)
				return
			}
			v, err := h(ctx, b, r)
			if err != nil {
				var he *localapi.HTTPError
				if errors.As(err, &he) && he.Code < 500 {
					http.Error(w, he.Msg, he.Code)
					return
				}
				if s.Log != nil {
					s.Log.Error("window request failed", "path", r.URL.Path, "err", err)
				}
				http.Error(w, "something went wrong; see the agent log", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(v)
		})
	}
	api("GET /api/status", func(ctx context.Context, b Backend, _ *http.Request) (any, error) { return b.Status(ctx) })
	api("GET /api/learning", func(ctx context.Context, b Backend, _ *http.Request) (any, error) { return b.Learning(ctx) })
	api("GET /api/lists", func(ctx context.Context, b Backend, _ *http.Request) (any, error) { return b.Lists(ctx) })
	api("GET /api/check", func(ctx context.Context, _ Backend, _ *http.Request) (any, error) {
		if s.Check == nil {
			return []selfcheck.Result{}, nil
		}
		return s.Check(ctx), nil
	})
	api("GET /api/alerts", func(ctx context.Context, b Backend, r *http.Request) (any, error) {
		q := store.AlertQuery{Limit: 200, Newest: true}
		if r.URL.Query().Get("show") != "all" {
			q.State = store.AlertNew
		}
		a, err := b.Alerts(ctx, q)
		if a == nil {
			a = []store.Alert{}
		}
		return a, err
	})
	api("POST /api/alerts/{id}/{action}", func(ctx context.Context, b Backend, r *http.Request) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, &localapi.HTTPError{Code: 400, Msg: "bad id"}
		}
		switch r.PathValue("action") {
		case "ok":
			return b.AlertOK(ctx, id)
		case "mute":
			return b.AlertMute(ctx, id)
		}
		return nil, &localapi.HTTPError{Code: 404, Msg: "unknown action"}
	})
	api("POST /api/lists/{list}/{action}", func(ctx context.Context, b Backend, r *http.Request) (any, error) {
		var req localapi.RuleRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			return nil, &localapi.HTTPError{Code: 400, Msg: "bad request"}
		}
		switch r.PathValue("list") + "/" + r.PathValue("action") {
		case "watch/add":
			return b.WatchAdd(ctx, req)
		case "ignore/remove":
			return b.IgnoreRemove(ctx, req)
		}
		return nil, &localapi.HTTPError{Code: 403, Msg: "this change makes trafficam quieter, so it needs an administrator: use 'trafficam lists' in an admin terminal"}
	})
	return s.guard(m)
}

// guard applies the checks that every request must pass.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.Host != s.Addr() {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOriginPost requires the custom header (other sites' pages cannot send
// it without a CORS pre-flight, which we never approve) and, if the browser
// sent an Origin, that it is us.
func sameOriginPost(r *http.Request, addr string) bool {
	if r.Header.Get("X-Trafficam") != "1" {
		return false
	}
	o := r.Header.Get("Origin")
	return o == "" || o == "http://"+addr
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, t string) {
	s.mu.Lock()
	exp, ok := s.tickets[t]
	delete(s.tickets, t) // one use only
	var sid string
	if ok && time.Now().Before(exp) {
		sid = randHex(32)
		s.sessions[sid] = time.Now().Add(s.ttl(s.SessionTTL))
	}
	s.gcLocked()
	s.mu.Unlock()
	if sid == "" {
		if s.hasSession(r) { // an old link, but already signed in
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		denied(w)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "tc", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.ttl(s.SessionTTL).Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther) // drops the ticket from the address bar
}

func (s *Server) hasSession(r *http.Request) bool {
	c, err := r.Cookie("tc")
	if err != nil || len(c.Value) != 64 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, exp := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(sid), []byte(c.Value)) == 1 && time.Now().Before(exp) {
			return true
		}
	}
	return false
}

// launch hands "trafficam ui" a ticket when it proves it can read the
// user's private launcher file.
func (s *Server) launch(w http.ResponseWriter, r *http.Request) {
	want := "Bearer " + s.LauncherSecret()
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		http.Error(w, "refused", http.StatusForbidden)
		return
	}
	fmt.Fprint(w, s.TicketURL())
}

func denied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>trafficam</title>
<body><h1>trafficam</h1><p>This link has expired or was already used.</p>
<p>Open trafficam again from a notification, or run <code>trafficam ui</code>.</p></body>`)
}
