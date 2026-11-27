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
//
// Optional offline lists, all off unless a file is given (see docs/ARCHITECTURE.md):
//
//	-blocklist FILE   known-bad snapshot: matches always alert
//	-watch FILE       your "alert me anyway" list
//	-ignore FILE      your "ignore" list
//	-asn FILE         offline CIDR -> ASN,country table
//
// "-blocklist pack" and "-prior pack" take the file from the installed,
// signed knowledge pack (docs/PACKS.md); the ASN table and the trusted OS
// list are used from the pack automatically when it has them.
//
//	trafficam pack install FILE [-data DIR]   verify and install a knowledge pack
//	trafficam pack status [-data DIR]         show the installed pack
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
	"github.com/Venkatesan7G/trafficam/internal/pack"
	"github.com/Venkatesan7G/trafficam/internal/replay"
	"github.com/Venkatesan7G/trafficam/internal/rules"
	"github.com/Venkatesan7G/trafficam/internal/service"
	"github.com/Venkatesan7G/trafficam/internal/store"
	"github.com/Venkatesan7G/trafficam/internal/trustos"
)

func main() {
	if len(os.Args) < 2 {
		if runningAsService() { // started by the Windows Service Control Manager
			os.Args = append(os.Args, "service", "run")
		} else {
			fmt.Fprintln(os.Stderr, "usage: trafficam demo|record|replay|dump|live|service|pack [flags]")
			os.Exit(2)
		}
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "pack" {
		if err := packCommand(args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if cmd == "service" {
		// "trafficam service <action> [flags]": the action comes before the flags.
		if err := serviceCommand(args); err != nil {
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
	fs.StringVar(&lf.blocklist, "blocklist", "", "known-bad snapshot file, or \"pack\" (opt-in)")
	fs.StringVar(&lf.watch, "watch", "", "your alert-anyway list")
	fs.StringVar(&lf.ignore, "ignore", "", "your ignore list")
	fs.StringVar(&lf.asn, "asn", "", "offline ASN/country table (CSV)")
	fs.StringVar(&lf.prior, "prior", "", "head C prior-risk weights (TCW1 file, or \"pack\"); empty = head C off")
	fs.BoolVar(&lf.trustOS, "trust-os", true, "do not raise novelty alerts for core OS services (lists and model still apply)")
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
type listFiles struct {
	blocklist, watch, ignore, asn, prior string
	trustOS                              bool
}

// fromPack resolves the "pack" value of -blocklist / -prior, and uses the
// pack's ASN table when -asn is not given. A pack that fails verification is
// ignored as a whole, loudly, and never used partly.
func (lf *listFiles) fromPack(dir string, log *slog.Logger) (*pack.Installed, error) {
	keys, err := pack.TrustedKeys()
	if err != nil {
		return nil, err
	}
	inst, err := pack.Load(dir, keys)
	if err != nil {
		log.Error("installed knowledge pack failed verification and is NOT used", "err", err)
		inst = nil
	} else if inst != nil {
		log.Info("knowledge pack", "seq", inst.Manifest.Seq, "created", inst.Manifest.Created, "signed_by", inst.SignedBy)
		if t, err := time.Parse("2006-01-02", inst.Manifest.Created); err == nil && time.Since(t) > 90*24*time.Hour {
			log.Warn("knowledge pack is more than 90 days old; its known-bad list is getting stale", "created", inst.Manifest.Created)
		}
	}
	for _, f := range []struct {
		v    *string
		kind string
	}{{&lf.blocklist, pack.KindBlocklist}, {&lf.prior, pack.KindPrior}} {
		if *f.v != "pack" {
			continue
		}
		if *f.v = inst.Path(f.kind); *f.v == "" {
			return nil, fmt.Errorf("-%s pack: no verified knowledge pack with a %s file is installed (see trafficam pack status)", f.kind, f.kind)
		}
	}
	if lf.asn == "" {
		lf.asn = inst.Path(pack.KindASN)
	}
	return inst, nil
}

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

	inst, err := lf.fromPack(dir, log)
	if err != nil {
		return err
	}
	var trusted *trustos.List
	if lf.trustOS {
		trusted = trustos.Default()
		if p := inst.Path(pack.KindTrustedOS); p != "" {
			if trusted, err = trustos.Load(p); err != nil {
				return err
			}
		}
	}

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
	tasks = append(tasks, service.Task{Name: "nightly-training",
		Run: func(ctx context.Context) error { learner.Loop(ctx); return nil }})

	scorer, err := rules.NewScorer(rules.Config{
		Baseline:  &baseline.Tracker{B: st},
		Blocklist: lists[0], AlertAnyway: lists[1], Ignore: lists[2], TrustedOS: trusted,
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
	if err := svc.Run(ctx); err != nil {
		return err
	}
	fmt.Printf("done: flows=%d rows=%d dropped=%d alerts=%d panics=%d\n",
		svc.Stats.Flows.Load(), svc.Stats.Rows.Load(), svc.Stats.Dropped.Load(),
		svc.Stats.Alerts.Load(), svc.Stats.Panics.Load())
	return nil
}

// packCommand: "trafficam pack install FILE | status".
func packCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trafficam pack install FILE | status [-data DIR]")
	}
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data folder")
	fs.Parse(args[1:])
	keys, err := pack.TrustedKeys()
	if err != nil {
		return err
	}
	switch args[0] {
	case "install":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: trafficam pack install [-data DIR] FILE")
		}
		inst, err := pack.Install(fs.Arg(0), *data, keys)
		if err != nil {
			return err
		}
		fmt.Printf("installed knowledge pack %d (%s), signed by %s\n", inst.Manifest.Seq, inst.Manifest.Created, inst.SignedBy)
		fmt.Println("restart trafficam to use it")
		return nil
	case "status":
		inst, err := pack.Load(*data, keys)
		if err != nil {
			return err
		}
		if inst == nil {
			fmt.Println("no knowledge pack installed")
			return nil
		}
		fmt.Printf("knowledge pack %d (%s), signed by %s, verified\n", inst.Manifest.Seq, inst.Manifest.Created, inst.SignedBy)
		for _, f := range inst.Manifest.Files {
			fmt.Printf("  %-20s %s\n", f.Name, f.Kind)
		}
		return nil
	}
	return fmt.Errorf("unknown pack action %q (want install or status)", args[0])
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
