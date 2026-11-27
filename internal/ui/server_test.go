package ui

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

type fakeBackend struct {
	muted []int64
	watch []string
}

func (f *fakeBackend) Status(context.Context) (localapi.Status, error) {
	return localapi.Status{Collector: "x", Unread: 1}, nil
}
func (f *fakeBackend) Alerts(context.Context, store.AlertQuery) ([]store.Alert, error) {
	return []store.Alert{{ID: 1, Program: "curl", Host: "<script>x</script>", State: store.AlertNew}}, nil
}
func (f *fakeBackend) AlertOK(_ context.Context, id int64) (store.Alert, error) {
	return store.Alert{ID: id, State: store.AlertOK}, nil
}
func (f *fakeBackend) AlertMute(_ context.Context, id int64) (store.Alert, error) {
	f.muted = append(f.muted, id)
	return store.Alert{ID: id, State: store.AlertMuted}, nil
}
func (f *fakeBackend) Lists(context.Context) (localapi.ListsReply, error) {
	return localapi.ListsReply{}, nil
}
func (f *fakeBackend) WatchAdd(_ context.Context, r localapi.RuleRequest) (localapi.ListsReply, error) {
	f.watch = append(f.watch, r.Pattern)
	return localapi.ListsReply{}, nil
}
func (f *fakeBackend) IgnoreRemove(context.Context, localapi.RuleRequest) (localapi.ListsReply, error) {
	return localapi.ListsReply{}, nil
}
func (f *fakeBackend) Learning(context.Context) (localapi.Learning, error) {
	return localapi.Learning{}, nil
}

func start(t *testing.T) (*Server, *fakeBackend) {
	fb := &fakeBackend{}
	s := &Server{Connect: func(context.Context) (Backend, error) { return fb, nil }}
	l, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, l)
	return s, fb
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func TestTicketLoginIsOneTime(t *testing.T) {
	s, _ := start(t)
	base := "http://" + s.Addr()
	anon := client()
	if r, _ := anon.Get(base + "/"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("no ticket: %d", r.StatusCode)
	}
	if r, _ := anon.Get(base + "/api/status"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("api without session: %d", r.StatusCode)
	}
	u := s.TicketURL()
	c := client()
	r, err := c.Get(u)
	if err != nil || r.StatusCode != 200 || r.Request.URL.RawQuery != "" {
		t.Fatalf("login: %v %v %v", err, r.StatusCode, r.Request.URL)
	}
	if r, _ := c.Get(base + "/static/app.js"); r.StatusCode != 200 {
		t.Fatalf("static: %d", r.StatusCode)
	}
	// The same ticket in another browser (e.g. from history) is useless.
	if r, _ := client().Get(u); r.StatusCode != http.StatusForbidden {
		t.Fatalf("ticket reused: %d", r.StatusCode)
	}
	if r, _ := c.Get(base + "/api/status"); r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("status: %d", r.StatusCode)
	}
}

func TestRequestChecks(t *testing.T) {
	s, fb := start(t)
	base := "http://" + s.Addr()
	c := client()
	c.Get(s.TicketURL())

	// DNS rebinding: right IP, wrong Host header.
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.Host = "evil.example:" + strings.Split(s.Addr(), ":")[1]
	if r, _ := c.Do(req); r.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("wrong host: %d", r.StatusCode)
	}
	post := func(path string, hdr map[string]string, body string) int {
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	if code := post("/api/alerts/1/mute", nil, ""); code != http.StatusForbidden || len(fb.muted) != 0 {
		t.Fatalf("POST without header: %d", code)
	}
	if code := post("/api/alerts/1/mute", map[string]string{"X-Trafficam": "1", "Origin": "http://evil.example"}, ""); code != http.StatusForbidden {
		t.Fatalf("cross-origin POST: %d", code)
	}
	ok := map[string]string{"X-Trafficam": "1", "Origin": base}
	if code := post("/api/alerts/1/mute", ok, ""); code != 200 || len(fb.muted) != 1 {
		t.Fatalf("good POST: %d", code)
	}
	if code := post("/api/lists/watch/add", ok, `{"pattern":"x.example"}`); code != 200 || fb.watch[0] != "x.example" {
		t.Fatalf("watch add: %d", code)
	}
	if code := post("/api/lists/ignore/add", ok, `{"pattern":"x.example"}`); code != http.StatusForbidden {
		t.Fatalf("ignore add must need an admin: %d", code)
	}
}

func TestLauncher(t *testing.T) {
	s, _ := start(t)
	base := "http://" + s.Addr()
	req, _ := http.NewRequest("POST", base+"/launch", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusForbidden {
		t.Fatal("launcher without secret")
	}
	req, _ = http.NewRequest("POST", base+"/launch", nil)
	req.Header.Set("Authorization", "Bearer "+s.LauncherSecret())
	r, err := http.DefaultClient.Do(req)
	if err != nil || r.StatusCode != 200 {
		t.Fatal(err)
	}
	var b strings.Builder
	buf := make([]byte, 200)
	n, _ := r.Body.Read(buf)
	b.Write(buf[:n])
	if u, err := url.Parse(b.String()); err != nil || u.Query().Get("t") == "" {
		t.Fatalf("launch reply %q", b.String())
	}
}
