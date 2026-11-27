// Command trafficam is a passive, offline network watcher.
//
// This is the shared-core build. Real capture (Linux eBPF, Windows ETW) plugs
// in as a collector.Collector from separate work; until then the commands
// below use synthetic traffic or replay files so the whole pipeline runs.
//
//	trafficam demo   [-data DIR] [-n N]        run the pipeline on synthetic traffic
//	trafficam record [-data DIR] -out FILE     save synthetic traffic to a replay file
//	trafficam replay [-data DIR] FILE          run the pipeline on a replay file
//	trafficam dump   [-data DIR]               print what is stored
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/keyseal"
	"github.com/Venkatesan7G/trafficam/internal/replay"
	"github.com/Venkatesan7G/trafficam/internal/service"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: trafficam demo|record|replay|dump [flags]")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "folder for the encrypted database and key")
	n := fs.Int("n", 600, "demo/record: number of synthetic flows")
	out := fs.String("out", "capture.jsonl", "record: output file (.gz to compress)")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch cmd {
	case "demo":
		err = run(ctx, *data, syntheticSource(*n), true)
	case "record":
		err = doRecord(ctx, *out, *n)
	case "replay":
		if fs.NArg() != 1 {
			err = fmt.Errorf("replay needs a file argument")
			break
		}
		err = run(ctx, *data, &replay.Player{Path: fs.Arg(0)}, true)
	case "dump":
		err = dump(*data)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func syntheticSource(n int) collector.Collector {
	return &collector.Synthetic{
		Start: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC),
		Step:  5 * time.Second, Count: n, Surprise: n - 3,
	}
}

func doRecord(ctx context.Context, path string, n int) error {
	w, err := replay.Create(path)
	if err != nil {
		return err
	}
	rec := &replay.Recorder{Inner: syntheticSource(n), Out: w}
	err = rec.Run(ctx, func(_ event.Flow) {})
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	fmt.Println("recorded to", path)
	return err
}

func openStore(dir string) (*store.Store, error) {
	key, err := (&keyseal.MachineIDProvider{Path: filepath.Join(dir, "db.key")}).Key()
	if err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dir, "trafficam.db"), key)
}

func run(ctx context.Context, dir string, c collector.Collector, oneShot bool) error {
	st, err := openStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	svc, err := service.New(service.Config{
		Collector: c, Store: st, OneShot: oneShot,
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	if err := svc.Run(ctx); err != nil {
		return err
	}
	fmt.Printf("done: flows=%d rows=%d dropped=%d alerts=%d panics=%d\n",
		svc.Stats.Flows.Load(), svc.Stats.Rows.Load(), svc.Stats.Dropped.Load(),
		svc.Stats.Alerts.Load(), svc.Stats.Panics.Load())
	return nil
}

func dump(dir string) error {
	st, err := openStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	rows, err := st.Since(time.Unix(0, 0))
	if err != nil {
		return err
	}
	for _, r := range rows {
		m := r.Minute
		fmt.Printf("%s %-10s %s/%s %-24s :%-5d flows=%d in=%d out=%d\n",
			m.Start.Format("2006-01-02 15:04"), m.Program.Name, m.Proto, m.Dir, m.Host, m.Port, m.Flows, m.BytesIn, m.BytesOut)
	}
	return nil
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "trafficam")
	}
	return "trafficam-data"
}
