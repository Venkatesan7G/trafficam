// Package notify shows desktop notifications in the user's session.
//
// It runs inside "trafficam agent", a small program that runs as the logged-in
// user (the watcher service itself runs as root / SYSTEM and cannot draw on
// anyone's desktop). Linux uses the standard freedesktop notification service
// over the session D-Bus; Windows uses a toast notification.
//
// Everything shown comes from network data (host names come from DNS, which
// an attacker can choose), so Clean strips control characters, limits length,
// and each platform escapes text for its own format. Nothing is ever run or
// opened from notification text.
package notify

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Urgency controls how loud a notification is.
type Urgency int

const (
	Normal   Urgency = iota
	Critical         // stays on screen until dismissed (tamper alerts)
)

// Note is one notification.
type Note struct {
	Title   string
	Body    string
	Urgency Urgency
	// OpenURL, if set, is opened when the user clicks the notification
	// (the trafficam window, served on 127.0.0.1). Must be http://127.0.0.1.
	OpenURL string
}

// Desktop shows notifications.
type Desktop interface {
	Name() string
	Show(n Note) error
	// Check reports whether notifications can be shown right now
	// (used by the install-time self-check).
	Check() error
}

// Clean makes untrusted text safe to show: printable characters only, no
// line breaks, at most max runes.
func Clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case !unicode.IsPrint(r) || unicode.Is(unicode.Bidi_Control, r):
			continue // control and direction-override characters can disguise text
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// ForAlert turns a stored alert into a notification.
func ForAlert(a store.Alert) Note {
	prog := Clean(a.Program, 60)
	if prog == "" {
		prog = "A program"
	}
	if a.Service != "" {
		prog += " (" + Clean(a.Service, 40) + ")"
	}
	host := Clean(a.Host, 100)
	if host == "" {
		host = Clean(a.RemoteIP, 50)
	}
	title := fmt.Sprintf("%s contacted %s", prog, host)
	if a.Dir == "in" {
		title = fmt.Sprintf("%s accepted a connection from %s", prog, host)
	}
	var body []string
	for i, r := range a.Reasons {
		if i == 2 {
			body = append(body, fmt.Sprintf("+%d more reason(s)", len(a.Reasons)-2))
			break
		}
		body = append(body, Clean(r, 160))
	}
	detail := fmt.Sprintf("%s port %d", strings.ToUpper(Clean(a.Proto, 8)), a.Port)
	if a.Country != "" {
		detail += ", " + Clean(a.Country, 4)
	}
	body = append(body, detail)
	return Note{Title: Clean(title, 120), Body: strings.Join(body, "\n")}
}

// Summary is one notification standing in for many (so a burst of alerts
// does not become a burst of pop-ups).
func Summary(n int) Note {
	return Note{Title: fmt.Sprintf("trafficam: %d new alerts", n),
		Body: "Several programs did something unusual. Open trafficam to review them."}
}

// Tamper is the notification for a tamper report.
func Tamper(text string) Note {
	head, rest, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return Note{Title: "trafficam: possible tampering - " + Clean(head, 100),
		Body:    Clean(rest, 300) + "\nRead TAMPER-ALERT.txt in the trafficam data folder.",
		Urgency: Critical}
}
