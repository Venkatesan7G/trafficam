// Package selfcheck answers "is trafficam set up and working?". The
// installer runs it right after installing ("trafficam check"), and the
// trafficam window shows the same list.
package selfcheck

import (
	"context"
	"fmt"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
)

// Level is how a check went.
type Level string

const (
	Pass Level = "pass"
	Warn Level = "warn" // works, but something needs attention
	Fail Level = "fail"
)

// Result is one line of the check.
type Result struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"` // what the user can do about it
}

// Inputs are the things the check looks at. Nil funcs are skipped.
type Inputs struct {
	Status        func(ctx context.Context) (localapi.Status, error)
	Notifications func() error         // can the desktop show a notification?
	NotifyName    string               // e.g. "Windows toast notifications"
	Autostart     func() (bool, error) // does the agent start at login?
	AgentRunning  bool                 // asked from inside the running agent
	Now           func() time.Time
	// GroupHint is the fix shown when the service can't be reached (it
	// differs between Linux and Windows).
	GroupHint string
}

// Run performs every check and returns the results in a fixed order.
func Run(ctx context.Context, in Inputs) []Result {
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	var out []Result
	add := func(name string, lv Level, detail, fix string) {
		out = append(out, Result{Name: name, Level: lv, Detail: detail, Fix: fix})
	}

	var st localapi.Status
	var stErr error = fmt.Errorf("not checked")
	if in.Status != nil {
		st, stErr = in.Status(ctx)
	}
	if stErr != nil {
		add("Watcher service", Fail, "The trafficam service is not reachable: "+stErr.Error(),
			"Start the service (Windows: trafficam service start; Linux: sudo systemctl start trafficam). "+in.GroupHint)
	} else {
		add("Watcher service", Pass, fmt.Sprintf("Running since %s, using %s.", st.Started.Local().Format("Jan 2 15:04"), st.Collector), "")

		switch {
		case st.Tamper != "":
			add("Tamper check", Fail, "A tamper report is standing: "+firstLine(st.Tamper),
				"Read TAMPER-ALERT.txt in the trafficam data folder, then acknowledge it.")
		default:
			add("Tamper check", Pass, "No sign that the database or key was interfered with.", "")
		}

		switch age := now().Sub(st.LastFlow); {
		case st.LastFlow.IsZero() && now().Sub(st.Started) < 2*time.Minute:
			add("Network capture", Warn, "No traffic seen yet; the service started moments ago.", "Wait a minute and run the check again.")
		case st.LastFlow.IsZero():
			add("Network capture", Fail, "The service is running but has not seen any network traffic.",
				"Check the service log. Capture needs administrator (Windows) or root (Linux) rights.")
		case age > 10*time.Minute:
			add("Network capture", Warn, fmt.Sprintf("No traffic seen for %s.", age.Round(time.Minute)),
				"That is normal if this computer is offline; otherwise check the service log.")
		default:
			add("Network capture", Pass, fmt.Sprintf("Seeing traffic (%d connections since start).", st.Flows), "")
		}

		if st.Dropped > 0 || st.Panics > 0 {
			add("Health", Warn, fmt.Sprintf("%d observations dropped under load, %d recovered internal errors.", st.Dropped, st.Panics),
				"Nothing to do unless this keeps growing; the service log has details.")
		} else {
			add("Health", Pass, "No dropped observations and no internal errors.", "")
		}

		if d := st.Now.Sub(now()); d > 2*time.Minute || d < -2*time.Minute {
			add("Clock", Warn, fmt.Sprintf("The service's clock differs from this session's by %s.", d.Round(time.Second)),
				"Make sure the system time is set automatically.")
		}

		r := st.Ramp
		next := "full strength"
		if r.NextName != "" {
			next = fmt.Sprintf("%s starts in %d day(s)", r.NextName, r.NextIn)
		}
		add("Learning", Pass, fmt.Sprintf("Stage: %s, day %d (%s).", r.Stage, r.Day, next), "")
	}

	if in.Notifications != nil {
		if err := in.Notifications(); err != nil {
			add("Desktop notifications", Fail, err.Error(), "Log in to a desktop session that shows notifications.")
		} else {
			add("Desktop notifications", Pass, "Available ("+in.NotifyName+").", "")
		}
	}
	if in.Autostart != nil {
		on, err := in.Autostart()
		switch {
		case err != nil:
			add("Start at login", Warn, err.Error(), "")
		case on:
			add("Start at login", Pass, "The notification agent starts when you log in.", "")
		default:
			add("Start at login", Warn, "The notification agent does not start by itself, so you would miss alerts after a restart.",
				"Run: trafficam agent -autostart on")
		}
	}
	return out
}

// Worst is the most serious level in the results.
func Worst(rs []Result) Level {
	w := Pass
	for _, r := range rs {
		if r.Level == Fail {
			return Fail
		}
		if r.Level == Warn {
			w = Warn
		}
	}
	return w
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}
