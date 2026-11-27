package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/alerts"
	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/ramp"
	"github.com/Venkatesan7G/trafficam/internal/service"
	"github.com/Venkatesan7G/trafficam/internal/store"
	"github.com/Venkatesan7G/trafficam/internal/userlists"
)

// tamperFile is written by the tamper response when the key or database has
// been interfered with, and deleted when the user acknowledges it. While it
// exists the desktop agent keeps showing a loud alert.
const tamperFile = "TAMPER-ALERT.txt"

// bridge connects the service to the desktop: alerts are stored and handed
// to the agent in the user's session through the local API.
type bridge struct {
	hub  *alerts.Hub
	task *service.Task // nil when the local API is off
	svc  atomic.Pointer[service.Service]
}

func newBridge(st *store.Store, dir, collectorName string, lf listFiles, oneShot bool, log *slog.Logger) *bridge {
	b := &bridge{hub: &alerts.Hub{St: st, Log: log}}
	addr := lf.api
	if addr == "" && !oneShot {
		addr = localapi.DefaultAddr(dir)
	}
	if addr == "" || addr == "off" {
		return b // demo / replay: no API unless asked for
	}
	started := time.Now().UTC()
	listPath := func(flagVal string, k userlists.Kind) string {
		if flagVal != "" {
			return flagVal
		}
		return userlists.Path(dir, k)
	}
	lists := &localapi.Lists{
		Watch:  userlists.File{Path: listPath(lf.watch, userlists.Watch), Kind: userlists.Watch},
		Ignore: userlists.File{Path: listPath(lf.ignore, userlists.Ignore), Kind: userlists.Ignore},
	}
	srv := &localapi.Server{Hub: b.hub, Store: st, Actions: st, Lists: lists, Log: log, Status: func() localapi.Status {
		s := localapi.Status{Now: time.Now().UTC(), Started: started, Collector: collectorName}
		if at, err := st.InstalledAt(); err == nil {
			s.InstalledAt, s.Ramp = at, ramp.At(time.Since(at))
		}
		if svc := b.svc.Load(); svc != nil {
			x := &svc.Stats
			s.Flows, s.Rows, s.Alerts, s.Dropped = x.Flows.Load(), x.Rows.Load(), x.Alerts.Load(), x.Dropped.Load()
			s.Panics, s.Restarts = x.Panics.Load(), x.Restarts.Load()
			if n := x.LastFlow.Load(); n != 0 {
				s.LastFlow = time.Unix(0, n).UTC()
			}
		}
		if t, err := readSmall(filepath.Join(dir, tamperFile), 4096); err == nil {
			s.Tamper = t
		}
		return s
	}}
	b.task = &service.Task{Name: "local-api", Run: func(ctx context.Context) error {
		l, err := localapi.Listen(addr)
		if err != nil {
			return err
		}
		log.Info("desktop agent API listening", "addr", addr)
		return srv.Serve(ctx, l)
	}}
	return b
}

func readSmall(p string, max int64) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n]), nil
}
