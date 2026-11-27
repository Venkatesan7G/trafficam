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
//	trafficam lists [show|add|remove|edit|path] ...  view and change your watch and ignore lists
//	trafficam agent [-test] [-autostart on|off]       show alerts as desktop notifications (run as yourself)
//	trafficam status                                 ask the running watcher how it is doing
//	trafficam ui                                     open the trafficam window in your browser
//	trafficam check [-json]                          install-time self-check (exit code 1 on a problem)
//
// Optional offline lists, all off unless a file is given (see docs/ARCHITECTURE.md):
//
//	-blocklist FILE   known-bad snapshot: matches always alert
//	-watch FILE       your "alert me anyway" list (default: <data>/watch.txt if it exists)
//	-ignore FILE      your "ignore" list (default: <data>/ignore.txt if it exists)
//
// The watch and ignore lists are re-read automatically when they change.
//
//	-asn FILE         offline CIDR -> ASN,country table
//	-api ADDR         local socket/pipe for the desktop agent (live: on by default; demo/replay: off)
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
	"github.com/Venkatesan7G/trafficam/internal/userlists"
)

func main() {
	if len(os.Args) < 2 {
		if runningAsService() { // started by the Windows Service Control Manager
			os.Args = append(os.Args, "service", "run")
		} else {
			fmt.Fprintln(os.Stderr, "usage: trafficam demo|record|replay|dump|live|service|lists|agent|status|ui|check [flags]")
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
	if sub, ok := map[string]func([]string) error{"lists": listsCommand, "agent": agentCommand, "status": statusCommand,
		"ui": uiCommand, "check": checkCommand}[cmd]; ok {
		if err := sub(args); err != nil {
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
	fs.StringVar(&lf.prior, "prior", "", "head C prior-risk weights (TCW1 file); empty = head C off")
	fs.StringVar(&lf.api, "api", "", "local API socket/pipe for the desktop agent (default for live: the system one; demo/replay: off)")
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

func openStore(dir string) (*store.Store, error) {
	key, err := (&keyseal.MachineIDProvider{Path: filepath.Join(dir, "db.key")}).Key()
	if err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dir, "trafficam.db"), key)
}

// listFiles are the optional offline files named on the command line.
type listFiles struct{ blocklist, watch, ignore, asn, prior, api string }

func loadList(path string) (*blocklist.List, error) {
	if path == "" {
		return nil, nil // nil list = feature switched off
	}
	return blocklist.Load(path)
}

func run(ctx context.Context, dir string, c collector.Collector, oneShot bool, lf listFiles) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, err := openStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	known, err := loadList(lf.blocklist)
	if err != nil {
		return err
	}
	// Your own lists live in the data folder unless named on the command
	// line, and are re-read when they change ("trafficam lists add ...").
	var userLists [2]*blocklist.Reloading
	for i, k := range []userlists.Kind{userlists.Watch, userlists.Ignore} {
		p := []string{lf.watch, lf.ignore}[i]
		if p == "" {
			p = userlists.Path(dir, k)
		}
		if userLists[i], err = blocklist.NewReloading(p); err != nil {
			return fmt.Errorf("your %s list: %w", k, err)
		}
		k := k
		userLists[i].OnError = func(e error) {
			log.Error("your "+string(k)+" list has a mistake; still using the previous version", "err", e)
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
	tasks = append(tasks, service.Task{Name: "nightly-training",
		Run: func(ctx context.Context) error { learner.Loop(ctx); return nil }})

	scorer, err := rules.NewScorer(rules.Config{
		Baseline:  &baseline.Tracker{B: st},
		Blocklist: known, WatchSource: userLists[0], IgnoreSource: userLists[1],
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

	// Alerts are stored and passed to the desktop agent (trafficam agent).
	br := newBridge(st, dir, c.Name(), lf, oneShot, log)
	if br.task != nil {
		tasks = append(tasks, *br.task)
	}
	tasks = append(tasks, service.Every("prune-alerts", time.Hour, 24*time.Hour, func(context.Context) error {
		_, err := st.AlertsPruneBefore(time.Now().AddDate(0, 0, -90))
		return err
	}))

	svc, err := service.New(service.Config{
		Collector: c, Store: st, OneShot: oneShot, Scorer: scorer, Tasks: tasks, Enrich: enricher, Log: log,
		Notifier: br.hub,
	})
	if err != nil {
		return err
	}
	br.svc.Store(svc)
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
