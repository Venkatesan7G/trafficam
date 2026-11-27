package main

// The trafficam window (progress, alerts, lists, self-check) and the
// install-time self-check.
//
//	trafficam ui      open the trafficam window in your browser
//	trafficam check   check that trafficam is installed and working (exit code 1 on a problem)

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/notify"
	"github.com/Venkatesan7G/trafficam/internal/selfcheck"
	"github.com/Venkatesan7G/trafficam/internal/ui"
)

// launcherFile tells "trafficam ui" where the running agent's window is. It
// lives in the user's own config folder and only the user can read it.
func launcherFile() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "trafficam", "window.json")
}

type launcher struct {
	Addr   string `json:"addr"`
	Secret string `json:"secret"`
	PID    int    `json:"pid"`
}

func writeLauncher(s *ui.Server) {
	p := launcherFile()
	if p == "" {
		return
	}
	b, _ := json.Marshal(launcher{Addr: s.Addr(), Secret: s.LauncherSecret(), PID: os.Getpid()})
	os.MkdirAll(filepath.Dir(p), 0o700)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, p)
	}
}

func removeLauncher(s *ui.Server) {
	p := launcherFile()
	var l launcher
	if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &l) == nil && l.Secret == s.LauncherSecret() {
		os.Remove(p)
	}
}

// askRunningAgent gets a fresh one-time link from the running agent.
func askRunningAgent() (string, error) {
	b, err := os.ReadFile(launcherFile())
	if err != nil {
		return "", err
	}
	var l launcher
	if err := json.Unmarshal(b, &l); err != nil {
		return "", err
	}
	if !strings.HasPrefix(l.Addr, "127.0.0.1:") {
		return "", errors.New("bad launcher file")
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+l.Addr+"/launch", nil)
	req.Header.Set("Authorization", "Bearer "+l.Secret)
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	u, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(u), "http://127.0.0.1:") {
		return "", fmt.Errorf("agent refused: %s", resp.Status)
	}
	return string(u), nil
}

// newWindow builds the window server used by the agent and by "trafficam ui".
func newWindow(addrs []string, desk notify.Desktop, agentRunning bool, log *slog.Logger) *ui.Server {
	return &ui.Server{
		Log: log,
		Connect: func(ctx context.Context) (ui.Backend, error) {
			c, err := localapi.Find(ctx, addrs)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		Check: func(ctx context.Context) []selfcheck.Result { return runCheck(ctx, addrs, desk, agentRunning) },
	}
}

func runCheck(ctx context.Context, addrs []string, desk notify.Desktop, agentRunning bool) []selfcheck.Result {
	return selfcheck.Run(ctx, selfcheck.Inputs{
		Status: func(ctx context.Context) (localapi.Status, error) {
			c, err := localapi.Find(ctx, addrs)
			if err != nil {
				return localapi.Status{}, err
			}
			return c.Status(ctx)
		},
		Notifications: desk.Check, NotifyName: desk.Name(),
		Autostart: autostartEnabled, AgentRunning: agentRunning, GroupHint: accessHint,
	})
}

func uiCommand(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	api := fs.String("api", "", "address of the watcher's local API (default: the usual places)")
	fs.Parse(args)
	if u, err := askRunningAgent(); err == nil {
		return openBrowser(u)
	}
	// No agent running: serve the window from here until Ctrl+C.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	w := newWindow(apiAddrs(*api), notify.New(), false, log)
	l, err := w.Listen()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	u := w.TicketURL()
	if err := openBrowser(u); err != nil {
		fmt.Println("open this link in your browser:", u)
	}
	fmt.Println("the trafficam window is open; press Ctrl+C here to close it (tip: 'trafficam agent' keeps it available)")
	return w.Serve(ctx, l)
}

func checkCommand(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	api := fs.String("api", "", "address of the watcher's local API (default: the usual places)")
	jsonOut := fs.Bool("json", false, "print the results as JSON (for installers)")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rs := runCheck(ctx, apiAddrs(*api), notify.New(), false)
	if *jsonOut {
		json.NewEncoder(os.Stdout).Encode(rs)
	} else {
		icon := map[selfcheck.Level]string{selfcheck.Pass: "ok  ", selfcheck.Warn: "WARN", selfcheck.Fail: "FAIL"}
		for _, r := range rs {
			fmt.Printf("[%s] %s: %s\n", icon[r.Level], r.Name, r.Detail)
			if r.Fix != "" {
				fmt.Printf("       fix: %s\n", r.Fix)
			}
		}
	}
	if selfcheck.Worst(rs) == selfcheck.Fail {
		os.Exit(1)
	}
	return nil
}
