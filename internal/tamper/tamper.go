// Package tamper decides what happens when trafficam's own files have been
// interfered with: the key cannot be unsealed, the database cannot be opened
// with its key, or either file is deleted or swapped while trafficam runs.
//
// The response, in this order, every time:
//
//  1. Loud alert. A plain-text report is written to <data>/TAMPER-ALERT.txt
//     (first line is a short headline), logged at ERROR, and passed to the
//     Alerter. The file stays until the user acknowledges it
//     ("trafficam tamper ack" or deleting the file), and the alert is raised
//     again at every start until then. It is never silent.
//  2. Self-destruct. The key file is overwritten and deleted (and the TPM key
//     on Windows), then the database and the learned model file are deleted.
//     With PolicyQuarantine they are moved into a "tampered-<time>" folder
//     instead, for anyone who wants to investigate.
//  3. Fresh start. A new key and an empty database are created, so the PC is
//     never left unwatched. Learning starts again from "Listening".
//
// What this protects: nobody can read your history from a tampered setup, and
// any tampering that trafficam can see is announced. What it cannot do: stop
// an attacker with administrator/root rights from deleting everything. Such
// an attacker could also delete the alert file, or stop trafficam first.
// See docs/TAMPER.md.
package tamper

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/keyseal"
)

// AlertFile is the name of the report in the data folder. Other parts of
// trafficam (the notification agent) watch for it: plain UTF-8, first line is
// the headline. Keep this contract stable.
const AlertFile = "TAMPER-ALERT.txt"

// ErrTampered is returned (wrapped) when tampering was detected and handled.
var ErrTampered = errors.New("tamper: trafficam's own files were tampered with")

// Policy says what self-destruct does with the old files.
type Policy int

const (
	PolicyDestroy    Policy = iota // delete (the default)
	PolicyQuarantine               // move into tampered-<time>/ (still unreadable: the key is destroyed)
)

// ParsePolicy reads the -on-tamper flag.
func ParsePolicy(s string) (Policy, error) {
	switch s {
	case "", "destroy":
		return PolicyDestroy, nil
	case "quarantine":
		return PolicyQuarantine, nil
	}
	return 0, fmt.Errorf("tamper: unknown policy %q (want destroy or quarantine)", s)
}

// Report describes one tamper event.
type Report struct {
	When      time.Time
	What      string   // short headline, e.g. "database key cannot be unsealed"
	Detail    string   // the underlying error or observation
	Destroyed []string // files destroyed or quarantined
	Pending   bool     // true when re-raised from an earlier, unacknowledged event
}

// Text is the content of AlertFile.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "TRAFFICAM TAMPER ALERT: %s\n\n", r.What)
	fmt.Fprintf(&b, "When:   %s\n", r.When.Format(time.RFC3339))
	fmt.Fprintf(&b, "Detail: %s\n", r.Detail)
	if len(r.Destroyed) > 0 {
		b.WriteString("\nTo protect your history, these were destroyed and can no longer be read:\n")
		for _, f := range r.Destroyed {
			fmt.Fprintf(&b, "  - %s\n", f)
		}
	}
	b.WriteString(`
What it means: something changed trafficam's own key or database, or
deleted them. It may be malware trying to hide what it did, a disk fault, or
a person resetting trafficam by hand. trafficam has started again with a new
key and an empty history, so it will spend the next days re-learning.

What to do: if you did not do this yourself, check this PC (for example with
your antivirus). To dismiss this alert, run "trafficam tamper ack" or delete
this file.
`)
	return b.String()
}

// Alerter shows a tamper report to the user. It must not block for long.
type Alerter interface {
	TamperAlert(r Report)
}

// LogAlerter logs at ERROR. The file is written by Guard itself.
type LogAlerter struct{ Log *slog.Logger }

func (a LogAlerter) TamperAlert(r Report) {
	l := a.Log
	if l == nil {
		l = slog.Default()
	}
	msg := "TAMPER ALERT"
	if r.Pending {
		msg = "TAMPER ALERT (not yet acknowledged)"
	}
	l.Error(msg, "what", r.What, "when", r.When.Format(time.RFC3339), "detail", r.Detail,
		"destroyed", r.Destroyed, "dismiss", "trafficam tamper ack")
}

// Guard owns the tamper response for one data folder.
type Guard struct {
	Dir    string
	Key    *keyseal.Sealed
	DBPath string
	// Learned lists other files built from the history (the model) that are
	// destroyed with it.
	Learned []string
	Policy  Policy
	Alert   Alerter          // default LogAlerter
	Now     func() time.Time // default time.Now
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Guard) alerter() Alerter {
	if g.Alert != nil {
		return g.Alert
	}
	return LogAlerter{}
}

func (g *Guard) alertPath() string { return filepath.Join(g.Dir, AlertFile) }

// Pending returns the text of an unacknowledged alert, if there is one.
func Pending(dir string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(dir, AlertFile))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Ack dismisses the alert.
func Ack(dir string) error {
	err := os.Remove(filepath.Join(dir, AlertFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// RaisePending re-raises an unacknowledged alert from an earlier run.
func (g *Guard) RaisePending() {
	text, ok := Pending(g.Dir)
	if !ok {
		return
	}
	head, _, _ := strings.Cut(text, "\n")
	head = strings.TrimPrefix(head, "TRAFFICAM TAMPER ALERT: ")
	g.alerter().TamperAlert(Report{When: g.now(), What: head,
		Detail: "see " + g.alertPath(), Pending: true})
}

// Trip runs the full response: destroy (or quarantine), write the report,
// alert. It returns the report. Errors while destroying are put in the
// report rather than stopping the alert: the alert must always go out.
func (g *Guard) Trip(what string, detail error) Report {
	r := Report{When: g.now(), What: what}
	if detail != nil {
		r.Detail = detail.Error()
	}
	var problems []string
	files := append([]string{g.DBPath, g.DBPath + "-wal", g.DBPath + "-shm", g.DBPath + "-journal"}, g.Learned...)

	// The key first: once it is gone, everything else is unreadable anyway.
	if _, err := os.Stat(g.Key.Path); err == nil {
		if g.Policy == PolicyQuarantine {
			// Keep a copy of the sealed blob for investigation; it is useless
			// once the TPM key is deleted (Windows) and on any other PC.
			if _, err := g.quarantine(g.Key.Path, r.When, true); err != nil {
				problems = append(problems, err.Error())
			}
		}
		if err := g.Key.Destroy(); err != nil {
			problems = append(problems, "key: "+err.Error())
		} else {
			r.Destroyed = append(r.Destroyed, g.Key.Path+" (database key)")
		}
	}
	if err := g.Key.DeleteTPMKeys(); err != nil {
		problems = append(problems, "TPM key: "+err.Error())
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		var err error
		if g.Policy == PolicyQuarantine {
			var to string
			if to, err = g.quarantine(f, r.When, false); err == nil {
				r.Destroyed = append(r.Destroyed, f+" (moved to "+to+")")
			}
		} else if err = os.Remove(f); err == nil {
			r.Destroyed = append(r.Destroyed, f)
		}
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		r.Detail += "\nProblems while destroying: " + strings.Join(problems, "; ")
	}
	if err := keyseal.WriteFileAtomic(g.alertPath(), []byte(r.Text()), 0o644); err != nil {
		r.Detail += "\nCould not write " + g.alertPath() + ": " + err.Error()
	}
	g.alerter().TamperAlert(r)
	return r
}

func (g *Guard) quarantine(f string, when time.Time, copyOnly bool) (string, error) {
	dir := filepath.Join(g.Dir, "tampered-"+when.UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	to := filepath.Join(dir, filepath.Base(f))
	if copyOnly {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		return to, os.WriteFile(to, b, 0o600)
	}
	return to, os.Rename(f, to)
}
