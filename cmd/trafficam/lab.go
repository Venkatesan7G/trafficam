package main

// Measurement commands (see docs/VALIDATION.md). They read recorded traffic
// and never touch the network or the live watcher.
//
//	trafficam export [-data DIR] -out FILE      save the database's minute rows to a file
//	trafficam eval   [-data DIR | -in FILE] ... replay through rules / model and report alerts per day
//	trafficam attacks [eval flags] [-labels FILE] plant attacks (or read VM labels) and compare arms
//	trafficam tune    [eval flags] ...          try many novelty thresholds and rank them

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/lab"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/rules"
)

// labCommands are dispatched before the main flag set (they have their own flags).
var labCommands = map[string]func([]string) error{
	"export":  exportCommand,
	"eval":    evalCommand,
	"attacks": attacksCommand,
	"tune":    tuneCommand,
}

func exportCommand(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "trafficam data folder to read")
	out := fs.String("out", "trafficam-minutes.jsonl.gz", "output file (.gz to compress)")
	fs.Parse(args)
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	d, err := lab.FromStore(st)
	if err != nil {
		return err
	}
	if err := lab.WriteMinutes(*out, d); err != nil {
		return err
	}
	fmt.Printf("exported %d minute rows (%d days) to %s\n", len(d.Rows), d.Days(), *out)
	fmt.Println("This file lists the programs and destinations this PC used. Review it before sharing it.")
	return nil
}

// evalFlags are shared with the attack and tuning commands.
type evalFlags struct {
	data, in    string
	synthetic   int
	arms        string
	prior       string
	tz          string
	trainCap    time.Duration
	jsonOut     string
	private     bool
	top         int
	quiet       bool
	lists       listFiles
	grace, age  time.Duration
	maxHosts    int
	installedAt string
}

func (e *evalFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&e.data, "data", defaultDataDir(), "read the rows from this trafficam data folder (ignored with -in)")
	fs.StringVar(&e.in, "in", "", "read a minutes file (from export) or a replay file instead of the database")
	fs.IntVar(&e.synthetic, "synthetic", 0, "use N days of made-up traffic instead (to try the tool)")
	fs.StringVar(&e.arms, "arms", "rules,rules+model", "comma list of: rules, rules+model, rules+model+prior")
	fs.StringVar(&e.prior, "prior", "", "head C weights for the rules+model+prior arm")
	fs.StringVar(&e.tz, "tz", "Local", "time zone for days and the 03:00 nightly job (e.g. Europe/Berlin)")
	fs.DurationVar(&e.trainCap, "train-cap", 60*time.Second, "time limit per nightly training (live uses 60s)")
	fs.StringVar(&e.jsonOut, "json", "", "also write the full results as JSON to this file")
	fs.BoolVar(&e.private, "private", false, "hide program paths, hosts and reasons in the report (safe to share)")
	fs.IntVar(&e.top, "top", 15, "alerts listed for review")
	fs.BoolVar(&e.quiet, "quiet", false, "no progress lines")
	fs.StringVar(&e.lists.blocklist, "blocklist", "", "known-bad snapshot file")
	fs.StringVar(&e.lists.watch, "watch", "", "your alert-anyway list")
	fs.StringVar(&e.lists.ignore, "ignore", "", "your ignore list")
	fs.DurationVar(&e.grace, "grace", 0, "rules: install grace (default 48h)")
	fs.DurationVar(&e.age, "program-age", 0, "rules: age before a program counts as settled (default 72h)")
	fs.IntVar(&e.maxHosts, "max-hosts", 0, "rules: programs with more known destinations are left to the model (default 20)")
}

func (e *evalFlags) load() (*lab.Data, *time.Location, error) {
	loc, err := time.LoadLocation(e.tz)
	if err != nil {
		return nil, nil, fmt.Errorf("-tz: %w", err)
	}
	switch {
	case e.synthetic > 0:
		return lab.Synthetic(time.Date(2026, 3, 2, 0, 0, 0, 0, loc), e.synthetic, 1), loc, nil
	case e.in != "":
		d, err := lab.Load(e.in)
		return d, loc, err
	default:
		st, err := openStore(e.data)
		if err != nil {
			return nil, nil, err
		}
		defer st.Close()
		d, err := lab.FromStore(st)
		return d, loc, err
	}
}

func (e *evalFlags) rulesConfig() (rules.Config, error) {
	c := rules.Config{InstallGrace: e.grace, MinProgramAge: e.age, MaxHostsForNovelty: e.maxHosts}
	var err error
	if c.Blocklist, err = loadList(e.lists.blocklist); err != nil {
		return c, err
	}
	if c.AlertAnyway, err = loadList(e.lists.watch); err != nil {
		return c, err
	}
	c.Ignore, err = loadList(e.lists.ignore)
	return c, err
}

func (e *evalFlags) buildArms() ([]lab.Arm, error) {
	rc, err := e.rulesConfig()
	if err != nil {
		return nil, err
	}
	var arms []lab.Arm
	for _, a := range strings.Split(e.arms, ",") {
		switch a = strings.TrimSpace(a); a {
		case "rules":
			arms = append(arms, lab.Arm{Name: a, Rules: rc})
		case "rules+model":
			arms = append(arms, lab.Arm{Name: a, Model: true, Rules: rc})
		case "rules+model+prior":
			if e.prior == "" {
				return nil, fmt.Errorf("arm %s needs -prior FILE", a)
			}
			hc, err := loadPrior(e.prior)
			if err != nil {
				return nil, err
			}
			arms = append(arms, lab.Arm{Name: a, Model: true, Prior: hc, Rules: rc})
		case "":
		default:
			return nil, fmt.Errorf("unknown arm %q (want rules, rules+model or rules+model+prior)", a)
		}
	}
	return arms, nil
}

func loadPrior(path string) (*model.HeadC, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	w, err := model.DecodeWeights(raw)
	if err != nil {
		return nil, err
	}
	return model.LoadHeadC(w)
}

func (e *evalFlags) options(loc *time.Location) lab.Options {
	nc := model.DefaultNightlyConfig()
	nc.Train.TimeCap = e.trainCap
	opt := lab.Options{Loc: loc, Nightly: nc}
	if !e.quiet {
		last := time.Time{}
		opt.Progress = func(s string) {
			if time.Since(last) > 2*time.Second {
				fmt.Fprintln(os.Stderr, "  replaying", s)
				last = time.Now()
			}
		}
	}
	return opt
}

// runArms replays every arm and summarises it.
func runArms(ctx context.Context, d *lab.Data, arms []lab.Arm, opt lab.Options, grace time.Duration) ([]*lab.Result, []*lab.Summary, error) {
	var res []*lab.Result
	var sums []*lab.Summary
	for _, a := range arms {
		r, err := lab.Run(ctx, d, a, opt)
		if err != nil {
			return nil, nil, fmt.Errorf("arm %s: %w", a.Name, err)
		}
		res = append(res, r)
		sums = append(sums, lab.Summarise(r, grace))
	}
	return res, sums, nil
}

func evalCommand(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	var e evalFlags
	e.register(fs)
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	d, loc, err := e.load()
	if err != nil {
		return err
	}
	if len(d.Rows) == 0 {
		return fmt.Errorf("no rows to replay in %s", d.Source)
	}
	arms, err := e.buildArms()
	if err != nil {
		return err
	}
	_, sums, err := runArms(ctx, d, arms, e.options(loc), e.grace)
	if err != nil {
		return err
	}
	lab.WriteText(os.Stdout, d, sums, lab.ReportOptions{Private: e.private, TopN: e.top})
	if e.jsonOut != "" {
		return writeJSON(e.jsonOut, sums, e.private)
	}
	return nil
}

func writeJSON(path string, v any, private bool) error {
	if private {
		// The JSON has hosts and programs in the alert lists; drop them.
		if sums, ok := v.([]*lab.Summary); ok {
			for _, s := range sums {
				s.Events = nil
			}
		}
		if cards, ok := v.([]*lab.Scorecard); ok {
			for _, c := range cards {
				c.Summary.Events = nil
			}
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func attacksCommand(args []string) error {
	fs := flag.NewFlagSet("attacks", flag.ExitOnError)
	var e evalFlags
	e.register(fs)
	labelsPath := fs.String("labels", "", "labels file from the VM scripts (lab/vm); without it, attacks are planted into the recording")
	at := fs.String("at", "", "when planted attacks start (2006-01-02T15:04, in -tz); default 75% through the recording")
	only := fs.String("only", "", "comma list of attack IDs to plant (default all)")
	seed := fs.Uint64("seed", 1, "random seed for planted attacks")
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	d, loc, err := e.load()
	if err != nil {
		return err
	}
	var labels lab.Labels
	var attacks []lab.Attack
	if *labelsPath != "" {
		labels, attacks, err = lab.ApplyLabels(*labelsPath, d)
	} else {
		opt := lab.InjectOptions{Seed: *seed}
		if *at != "" {
			if opt.At, err = time.ParseInLocation("2006-01-02T15:04", *at, loc); err != nil {
				return fmt.Errorf("-at: %w", err)
			}
		}
		if *only != "" {
			opt.Only = strings.Split(*only, ",")
		}
		d, labels, attacks, err = lab.Inject(d, opt)
	}
	if err != nil {
		return err
	}
	arms, err := e.buildArms()
	if err != nil {
		return err
	}
	res, _, err := runArms(ctx, d, arms, e.options(loc), e.grace)
	if err != nil {
		return err
	}
	var cards []*lab.Scorecard
	for _, r := range res {
		cards = append(cards, lab.Score(r, labels, attacks, e.grace))
	}
	lab.WriteComparison(os.Stdout, d, attacks, cards)
	lab.WriteFalseAlarmSources(os.Stdout, cards, e.private)
	if e.jsonOut != "" {
		return writeJSON(e.jsonOut, cards, e.private)
	}
	return nil
}

func tuneCommand(args []string) error {
	fs := flag.NewFlagSet("tune", flag.ExitOnError)
	var e evalFlags
	e.register(fs)
	graces := fs.String("graces", "12h,24h,48h,72h", "install grace values to try")
	ages := fs.String("ages", "24h,48h,72h,120h", "program-age values to try")
	hosts := fs.String("hosts", "5,10,20,40,80", "max-hosts values to try")
	withModel := fs.Bool("model", false, "include the model's alerts (runs the model once; slower)")
	noAttacks := fs.Bool("no-attacks", false, "measure false alarms only (no planted attacks)")
	labelsPath := fs.String("labels", "", "use a VM labels file instead of planted attacks")
	seed := fs.Uint64("seed", 1, "random seed for planted attacks")
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	g, err := parseDurations(*graces)
	if err != nil {
		return fmt.Errorf("-graces: %w", err)
	}
	a, err := parseDurations(*ages)
	if err != nil {
		return fmt.Errorf("-ages: %w", err)
	}
	var h []int
	for _, f := range strings.Split(*hosts, ",") {
		var n int
		if _, err := fmt.Sscan(strings.TrimSpace(f), &n); err != nil || n <= 0 {
			return fmt.Errorf("-hosts: bad value %q", f)
		}
		h = append(h, n)
	}
	d, loc, err := e.load()
	if err != nil {
		return err
	}
	var labels lab.Labels
	var attacks []lab.Attack
	switch {
	case *labelsPath != "":
		labels, attacks, err = lab.ApplyLabels(*labelsPath, d)
	case !*noAttacks:
		d, labels, attacks, err = plantWaves(d, *seed)
	}
	if err != nil {
		return err
	}
	base, err := e.rulesConfig()
	if err != nil {
		return err
	}
	opt := lab.TuneOptions{Options: e.options(loc), Base: base, Model: *withModel}
	if *withModel && e.prior != "" {
		if opt.Prior, err = loadPrior(e.prior); err != nil {
			return err
		}
	}
	if !e.quiet {
		opt.Log = func(s string) { fmt.Fprintln(os.Stderr, " ", s) }
	}
	rs, err := lab.Tune(ctx, d, labels, attacks, lab.Grid(g, a, h), opt)
	if err != nil {
		return err
	}
	lab.WriteTuning(os.Stdout, d, attacks, rs, *withModel, e.top)
	if e.jsonOut != "" {
		return writeJSON(e.jsonOut, rs, false)
	}
	return nil
}

// plantWaves plants three waves of attacks, so the thresholds that delay
// alerts after an install are tested too: right after install (30 h, inside
// most graces), while programs are still young (60 h), and once everything
// has settled (75 % through the recording, the full set).
func plantWaves(d *lab.Data, seed uint64) (*lab.Data, lab.Labels, []lab.Attack, error) {
	install := d.InstallTime()
	early := []string{"beacon-quiet", "exfil-new", "dga", "dropper"}
	var all []lab.Attack
	var labels lab.Labels
	for _, w := range []lab.InjectOptions{
		{At: install.Add(30 * time.Hour), MinHistory: 24 * time.Hour, Only: early, IDSuffix: "@30h", Gap: time.Hour},
		{At: install.Add(60 * time.Hour), MinHistory: 24 * time.Hour, Only: early, IDSuffix: "@60h", Gap: time.Hour},
		{},
	} {
		w.Seed, w.Prev = seed, labels
		nd, nl, at, err := lab.Inject(d, w)
		if err != nil {
			return nil, nil, nil, err
		}
		d, labels, all = nd, nl, append(all, at...)
	}
	return d, labels, all, nil
}

func parseDurations(s string) ([]time.Duration, error) {
	var out []time.Duration
	for _, f := range strings.Split(s, ",") {
		v, err := time.ParseDuration(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
