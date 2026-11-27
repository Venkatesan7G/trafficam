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
//	trafficam live   [-data DIR]               watch this PC's real traffic (needs admin/root)
//	trafficam service install|uninstall|start|stop   (Windows) run "live" as a Windows service
//	trafficam tamper status|ack [-data DIR]   show or dismiss a tamper alert (docs/TAMPER.md)
//
// Optional offline lists, all off unless a file is given (see docs/ARCHITECTURE.md):
//
//	-blocklist FILE   known-bad snapshot: matches always alert
//	-watch FILE       your "alert me anyway" list
//	-ignore FILE      your "ignore" list
//	-asn FILE         offline CIDR -> ASN,country table
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/aggregate"
	"github.com/Venkatesan7G/trafficam/internal/baseline"
	"github.com/Venkatesan7G/trafficam/internal/blocklist"
	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/enrich"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/keyseal"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/modelscore"
	"github.com/Venkatesan7G/trafficam/internal/replay"
	"github.com/Venkatesan7G/trafficam/internal/rules"
	"github.com/Venkatesan7G/trafficam/internal/service"
	"github.com/Venkatesan7G/trafficam/internal/store"
	"github.com/Venkatesan7G/trafficam/internal/tamper"
)

func main() {
	if len(os.Args) < 2 {
		if runningAsService() { // started by the Windows Service Control Manager
			os.Args = append(os.Args, "service", "run")
		} else {
			fmt.Fprintln(os.Stderr, "usage: trafficam demo|record|replay|dump|live|service|tamper [flags]")
			os.Exit(2)
		}
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "service" {
		// "trafficam service <action> [flags]": the action comes before the flags.
		if err := serviceCommand(args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if cmd == "tamper" {
		if err := tamperCommand(args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "folder for the encrypted database and key")
	n := fs.Int("n", 600, "demo/record: number of synthetic flows")
	out := fs.String("out", "capture.jsonl", "record: output file (.gz to compress)")
	var lf listFiles
	fs.StringVar(&lf.blocklist, "blocklist", "", "known-bad snapshot file (opt-in)")
	fs.StringVar(&lf.watch, "watch", "", "your alert-anyway list")
	fs.StringVar(&lf.ignore, "ignore", "", "your ignore list")
	fs.StringVar(&lf.asn, "asn", "", "offline ASN/country table (CSV)")
	fs.StringVar(&lf.onTamper, "on-tamper", "destroy", "if the key or database is tampered with: destroy, or quarantine (move aside)")
	fs.StringVar(&lf.prior, "prior", "", "head C prior-risk weights (TCW1 file); empty = head C off")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch cmd {
	case "demo":
		err = run(ctx, *data, syntheticSource(*n), true, lf)
	case "record":
		err = doRecord(ctx, *out, *n)
	case "replay":
		if fs.NArg() != 1 {
			err = fmt.Errorf("replay needs a file argument")
			break
		}
		err = run(ctx, *data, &replay.Player{Path: fs.Arg(0)}, true, lf)
	case "dump":
		err = dump(*data)
	case "live":
		err = runLive(ctx, *data, lf)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// runLive runs the pipeline on this PC's real traffic until ctx is
// cancelled. liveCollector comes from live_<os>.go.
func runLive(ctx context.Context, dir string, lf listFiles) error {
	c, err := liveCollector()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "trafficam: watching with %s, data in %s (Ctrl+C to stop)\n", c.Name(), dir)
	return run(ctx, dir, c, false, lf)
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

// guardFor sets up the tamper response for a data folder. The key is sealed
// with the strongest method this PC offers (TPM, then DPAPI on Windows or the
// machine id on Linux); see docs/KEYS.md and docs/TAMPER.md.
func guardFor(dir string, lf listFiles) (*tamper.Guard, error) {
	policy, err := tamper.ParsePolicy(lf.onTamper)
	if err != nil {
		return nil, err
	}
	kp := keyseal.Default(filepath.Join(dir, "db.key"))
	kp.Logf = func(format string, args ...any) { slog.Info(fmt.Sprintf(format, args...)) }
	return &tamper.Guard{
		Dir: dir, Key: kp, DBPath: filepath.Join(dir, "trafficam.db"),
		Learned: []string{filepath.Join(dir, "model.tcw")}, Policy: policy,
	}, nil
}

// openStoreReadOnly is for commands that only look (dump): tampering is
// reported, but nothing is destroyed; the watcher itself handles it.
func openStoreReadOnly(dir string) (*store.Store, error) {
	g, err := guardFor(dir, listFiles{})
	if err != nil {
		return nil, err
	}
	g.RaisePending()
	key, err := g.Check()
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("no database in %s yet", dir)
	}
	return store.Open(g.DBPath, key)
}

// listFiles are the optional offline files named on the command line.
// onTamper is the -on-tamper policy (destroy or quarantine).
type listFiles struct{ blocklist, watch, ignore, asn, prior, onTamper string }

func loadList(path string) (*blocklist.List, error) {
	if path == "" {
		return nil, nil // nil list = feature switched off
	}
	return blocklist.Load(path)
}

// run runs the pipeline with the tamper response around it: tampering found
// at start or while running is handled (alert, destroy, fresh start) and the
// pipeline starts again on the new, empty database.
func run(ctx context.Context, dir string, c collector.Collector, oneShot bool, lf listFiles) error {
	g, err := guardFor(dir, lf)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		err := runOnce(ctx, g, c, oneShot, lf)
		var d *tamper.Detected
		if !errors.As(err, &d) || attempt >= 3 {
			return err // attempt cap: a disk that keeps "tampering" is not worth a loop
		}
		g.Trip(d.What, d.Err) // the store is closed by now
	}
}

func runOnce(ctx context.Context, g *tamper.Guard, c collector.Collector, oneShot bool, lf listFiles) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dir := g.Dir
	st, err := g.Open()
	if err != nil {
		return err
	}
	defer st.Close()
	if m, err := g.Key.Method(); err == nil {
		log.Info("database key protected", "method", m)
	}
	watch, err := g.Watch()
	if err != nil {
		return err
	}
	ctx, stopForTamper := context.WithCancelCause(ctx)
	defer stopForTamper(nil)

	var lists [3]*blocklist.List
	for i, p := range []string{lf.blocklist, lf.watch, lf.ignore} {
		if lists[i], err = loadList(p); err != nil {
			return err
		}
	}
	var enricher aggregate.Enricher
	if lf.asn != "" {
		t, err := enrich.Load(lf.asn)
		if err != nil {
			return err
		}
		enricher = t
	}

	// The learning model: scores every row, trains itself nightly on the
	// stored history, and keeps its state in <data>/model.tcw. Head C is a user
	// switch (--prior); without it the model runs on its own.
	var prior *model.HeadC
	if lf.prior != "" {
		raw, err := os.ReadFile(lf.prior)
		if err != nil {
			return err
		}
		w, err := model.DecodeWeights(raw)
		if err != nil {
			return err
		}
		if prior, err = model.LoadHeadC(w); err != nil {
			return err
		}
	}
	learner, err := modelscore.New(modelscore.Config{
		ModelPath: filepath.Join(dir, "model.tcw"), History: st, Prior: prior, Log: log,
	})
	if err != nil {
		return err
	}
	var tasks []service.Task
	// Every 30 s: has someone changed, swapped or deleted our key or database?
	tasks = append(tasks, service.Every("tamper-watch", 30*time.Second, 30*time.Second, func(context.Context) error {
		if err := watch.Check(); err != nil {
			stopForTamper(err)
		}
		return nil
	}))
	tasks = append(tasks, service.Task{Name: "nightly-training",
		Run: func(ctx context.Context) error { learner.Loop(ctx); return nil }})

	scorer, err := rules.NewScorer(rules.Config{
		Baseline:  &baseline.Tracker{B: st},
		Blocklist: lists[0], AlertAnyway: lists[1], Ignore: lists[2],
	}, learner)
	if err != nil {
		return err
	}
	scorer.OnError = func(e error) { log.Error("scoring problem (rules still ran)", "err", e) }

	// Keep the database bounded: 35 days = the 30-day baseline plus a margin.
	// (The seen-counters used by the rules are kept; they are tiny.)
	tasks = append(tasks, service.Every("prune", time.Hour, 24*time.Hour, func(context.Context) error {
		_, err := st.PruneBefore(time.Now().AddDate(0, 0, -35))
		return err
	}))

	svc, err := service.New(service.Config{
		Collector: c, Store: st, OneShot: oneShot, Scorer: scorer, Tasks: tasks, Enrich: enricher, Log: log,
	})
	if err != nil {
		return err
	}
	err = svc.Run(ctx)
	if cause := context.Cause(ctx); errors.Is(cause, tamper.ErrTampered) {
		return cause
	}
	if err != nil {
		return err
	}
	fmt.Printf("done: flows=%d rows=%d dropped=%d alerts=%d panics=%d\n",
		svc.Stats.Flows.Load(), svc.Stats.Rows.Load(), svc.Stats.Dropped.Load(),
		svc.Stats.Alerts.Load(), svc.Stats.Panics.Load())
	return nil
}

// tamperCommand: "trafficam tamper status|ack [-data DIR]".
func tamperCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trafficam tamper status|ack [-data DIR]")
	}
	fs := flag.NewFlagSet("tamper", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data folder")
	fs.Parse(args[1:])
	switch args[0] {
	case "status":
		if text, ok := tamper.Pending(*data); ok {
			fmt.Print(text)
			return nil
		}
		fmt.Println("no tamper alert")
		return nil
	case "ack":
		if _, ok := tamper.Pending(*data); !ok {
			fmt.Println("no tamper alert to dismiss")
			return nil
		}
		if err := tamper.Ack(*data); err != nil {
			return err
		}
		fmt.Println("tamper alert dismissed")
		return nil
	}
	return fmt.Errorf("unknown tamper action %q (want status or ack)", args[0])
}

func dump(dir string) error {
	st, err := openStoreReadOnly(dir)
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
		fmt.Printf("%s %-10s %s/%s %-24s :%-5d flows=%d in=%d out=%d as=%d %s alert=%v\n",
			m.Start.Format("2006-01-02 15:04"), m.Program.Name, m.Proto, m.Dir, m.Host, m.Port, m.Flows, m.BytesIn, m.BytesOut, m.ASN, m.Country, r.Alerted)
	}
	return nil
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "trafficam")
	}
	return "trafficam-data"
}
