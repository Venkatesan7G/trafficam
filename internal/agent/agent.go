// Package agent is the small program that runs in the logged-in user's
// desktop session ("trafficam agent"). It asks the watcher service for new
// alerts over the local API and shows each one as a desktop notification.
//
// It is deliberately simple and harmless:
//
//   - It only reads from the service; it cannot change what the service does
//     to traffic (nothing can: the service is passive).
//   - If the service is not running it waits quietly and retries.
//   - A burst of alerts becomes one summary notification, so the desktop is
//     never flooded (at most MaxPerMinute pop-ups a minute).
//   - It remembers the last alert it showed (in the user's own config
//     folder), so alerts are not repeated after a restart, and alerts raised
//     while nobody was logged in are shown once, as a catch-up.
package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/notify"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// API is the part of localapi.Client the agent uses (faked in tests).
type API interface {
	Status(ctx context.Context) (localapi.Status, error)
	Alerts(ctx context.Context, q store.AlertQuery) ([]store.Alert, error)
	Wait(ctx context.Context, after int64) ([]store.Alert, error)
}

// Config sets the agent up. Zero values get the defaults in brackets.
type Config struct {
	// Connect returns a client for the service, trying the usual places.
	Connect func(ctx context.Context) (API, error)
	Desktop notify.Desktop
	// StatePath remembers the last alert shown [user config dir/trafficam/agent-state.json].
	StatePath string
	// WindowURL, if set, returns the address of the trafficam window; it is
	// opened when a notification is clicked.
	WindowURL func() string
	Log       *slog.Logger

	MaxPerMinute int           // [3] pop-ups per minute before alerts are summarised
	CatchUp      time.Duration // [24h] unread alerts this recent are shown on start
	TamperRepeat time.Duration // [4h] how often a tamper report is shown again while it stands
	StatusEvery  time.Duration // [1m]
	RetryMax     time.Duration // [1m] longest wait between reconnect attempts
	Now          func() time.Time
}

type state struct {
	LastID    int64 `json:"last_id"`
	Installed int64 `json:"installed"` // the service DB's install time; a new DB restarts IDs
}

// Agent is one running agent.
type Agent struct {
	cfg    Config
	st     state
	shown  []time.Time // when recent pop-ups were shown (rate limit)
	behind int         // alerts not shown individually because of the rate limit

	tamperText string
	tamperAt   time.Time
}

// New fills in defaults.
func New(cfg Config) *Agent {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.CatchUp, 24*time.Hour)
	def(&cfg.TamperRepeat, 4*time.Hour)
	def(&cfg.StatusEvery, time.Minute)
	def(&cfg.RetryMax, time.Minute)
	if cfg.MaxPerMinute <= 0 {
		cfg.MaxPerMinute = 3
	}
	if cfg.StatePath == "" {
		if d, err := os.UserConfigDir(); err == nil {
			cfg.StatePath = filepath.Join(d, "trafficam", "agent-state.json")
		}
	}
	a := &Agent{cfg: cfg}
	a.load()
	return a
}

// Run shows alerts until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	first := min(2*time.Second, a.cfg.RetryMax)
	wait, warned := first, false
	for ctx.Err() == nil {
		c, err := a.cfg.Connect(ctx)
		if err == nil {
			warned, wait = false, first
			err = a.session(ctx, c)
		}
		if ctx.Err() != nil {
			return nil
		}
		if !warned {
			a.cfg.Log.Warn("cannot reach the trafficam service; will keep trying", "err", err)
			warned = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if wait *= 2; wait > a.cfg.RetryMax {
			wait = a.cfg.RetryMax
		}
	}
	return nil
}

// session runs while the service is reachable.
func (a *Agent) session(ctx context.Context, c API) error {
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	a.cfg.Log.Info("connected to the trafficam service", "stage", st.Ramp.Stage, "unread", st.Unread)
	if inst := st.InstalledAt.Unix(); inst != a.st.Installed || st.LatestAlert < a.st.LastID {
		a.st = state{Installed: inst} // a fresh database: start counting again
	}
	a.checkTamper(st, true)

	// Catch up: unread alerts from while we were not running.
	missed, err := c.Alerts(ctx, store.AlertQuery{AfterID: a.st.LastID, State: store.AlertNew,
		Since: a.cfg.Now().Add(-a.cfg.CatchUp), Limit: 1000})
	if err != nil {
		return err
	}
	switch {
	case len(missed) > a.cfg.MaxPerMinute:
		a.show(notify.Summary(len(missed)), true)
	default:
		for _, al := range missed {
			a.showAlert(al)
		}
	}
	a.advance(st.LatestAlert)

	lastStatus := a.cfg.Now()
	for ctx.Err() == nil {
		got, err := c.Wait(ctx, a.st.LastID)
		if err != nil {
			return err
		}
		a.flushBehind()
		for _, al := range got {
			a.showAlert(al)
			a.advance(al.ID)
		}
		if a.cfg.Now().Sub(lastStatus) >= a.cfg.StatusEvery {
			lastStatus = a.cfg.Now()
			if st, err := c.Status(ctx); err == nil {
				a.checkTamper(st, false)
			}
		}
	}
	return ctx.Err()
}

func (a *Agent) showAlert(al store.Alert) {
	if al.State != store.AlertNew && al.State != "" {
		return // already handled in the trafficam window
	}
	if !a.allowed() {
		a.behind++
		return
	}
	a.show(notify.ForAlert(al), false)
}

// flushBehind shows one summary for alerts held back by the rate limit.
func (a *Agent) flushBehind() {
	if a.behind > 0 && a.allowed() {
		a.show(notify.Summary(a.behind), false)
		a.behind = 0
	}
}

func (a *Agent) allowed() bool {
	now := a.cfg.Now()
	keep := a.shown[:0]
	for _, t := range a.shown {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	a.shown = keep
	return len(a.shown) < a.cfg.MaxPerMinute
}

func (a *Agent) show(n notify.Note, force bool) {
	if !force && !a.allowed() {
		a.behind++
		return
	}
	if a.cfg.WindowURL != nil {
		n.OpenURL = a.cfg.WindowURL()
	}
	a.shown = append(a.shown, a.cfg.Now())
	if err := a.cfg.Desktop.Show(n); err != nil {
		a.cfg.Log.Error("could not show a notification", "title", n.Title, "err", err)
	}
}

// checkTamper shows a standing tamper report on connect, when it changes, and
// again every TamperRepeat. It is never rate-limited.
func (a *Agent) checkTamper(st localapi.Status, connected bool) {
	if st.Tamper == "" {
		a.tamperText = ""
		return
	}
	now := a.cfg.Now()
	if connected || st.Tamper != a.tamperText || now.Sub(a.tamperAt) >= a.cfg.TamperRepeat {
		a.tamperText, a.tamperAt = st.Tamper, now
		n := notify.Tamper(st.Tamper)
		if err := a.cfg.Desktop.Show(n); err != nil {
			a.cfg.Log.Error("could not show the tamper alert", "err", err)
		}
	}
}

func (a *Agent) advance(id int64) {
	if id > a.st.LastID {
		a.st.LastID = id
		a.save()
	}
}

func (a *Agent) load() {
	if a.cfg.StatePath == "" {
		return
	}
	if b, err := os.ReadFile(a.cfg.StatePath); err == nil {
		json.Unmarshal(b, &a.st)
	}
}

func (a *Agent) save() {
	if a.cfg.StatePath == "" {
		return
	}
	b, _ := json.Marshal(a.st)
	os.MkdirAll(filepath.Dir(a.cfg.StatePath), 0o700)
	tmp := a.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		os.Rename(tmp, a.cfg.StatePath)
	}
}

// ConnectAny returns a Connect function that tries each address in turn.
func ConnectAny(addrs []string) func(ctx context.Context) (API, error) {
	return func(ctx context.Context) (API, error) { return localapi.Find(ctx, addrs) }
}
