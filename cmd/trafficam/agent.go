package main

// "trafficam agent" runs in your desktop session (not as admin) and shows
// trafficam's alerts as desktop notifications. The watcher service runs as
// root / SYSTEM and cannot draw on your desktop itself, so it hands alerts to
// the agent over a local, OS-protected socket (Linux) or pipe (Windows).
//
//	trafficam agent                 run until you log out
//	trafficam agent -test           show one test notification and exit
//	trafficam agent -autostart on   start the agent every time you log in (off to undo)
//	trafficam status                print the watcher's status
//
// On Linux your user must be in the "trafficam" group to read alerts from a
// watcher running as root:  sudo groupadd -f trafficam && sudo usermod -aG trafficam $USER
// (then log out and in again). On Windows any logged-in user can.

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/agent"
	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/notify"
)

func apiAddrs(flagVal string) []string {
	if flagVal != "" {
		return strings.Split(flagVal, ",")
	}
	return localapi.CandidateAddrs(defaultDataDir())
}

func agentCommand(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	api := fs.String("api", "", "address of the watcher's local API (default: the usual places)")
	test := fs.Bool("test", false, "show one test notification and exit")
	auto := fs.String("autostart", "", "on: start the agent when you log in; off: stop doing that")
	fs.Parse(args)

	desk := notify.New()
	switch {
	case *test:
		if err := desk.Check(); err != nil {
			return err
		}
		if err := desk.Show(notify.Note{Title: "trafficam test notification",
			Body: "If you can read this, trafficam can reach you."}); err != nil {
			return err
		}
		fmt.Println("sent a test notification using", desk.Name())
		return nil
	case *auto != "":
		return setAutostart(*auto == "on")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := desk.Check(); err != nil {
		log.Warn("desktop notifications may not work", "err", err)
	}
	log.Info("trafficam agent started", "notifications", desk.Name())
	return agent.New(agent.Config{Connect: agent.ConnectAny(apiAddrs(*api)), Desktop: desk, Log: log}).Run(ctx)
}

func statusCommand(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	api := fs.String("api", "", "address of the watcher's local API (default: the usual places)")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := agent.ConnectAny(apiAddrs(*api))(ctx)
	if err != nil {
		return fmt.Errorf("the trafficam service is not reachable (is it running, and on Linux are you in the %q group?): %w", "trafficam", err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Stage:      %s (day %d, %.0f%% of the way to Guarding", st.Ramp.Stage, st.Ramp.Day, st.Ramp.Percent)
	if st.Ramp.NextName != "" {
		fmt.Printf("; %s in %d day(s)", st.Ramp.NextName, st.Ramp.NextIn)
	}
	fmt.Println(")")
	fmt.Printf("Capture:    %s, %d flows since %s", st.Collector, st.Flows, st.Started.Local().Format("Jan 2 15:04"))
	if !st.LastFlow.IsZero() {
		fmt.Printf(", last one %s ago", time.Since(st.LastFlow).Round(time.Second))
	}
	fmt.Println()
	fmt.Printf("Alerts:     %d unread\n", st.Unread)
	if st.Dropped+st.Panics > 0 {
		fmt.Printf("Problems:   %d flows dropped, %d recovered crashes, %d restarts\n", st.Dropped, st.Panics, st.Restarts)
	}
	if st.Tamper != "" {
		fmt.Printf("\n!! TAMPER ALERT !!\n%s\n", st.Tamper)
	}
	return nil
}
