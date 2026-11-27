// Package localapi is how programs in the user's desktop session (the
// notification agent, and later the trafficam window) talk to the watcher
// service, which runs as root / SYSTEM.
//
// Safety rules:
//
//   - It is NOT a network server. On Linux it listens on a Unix socket, on
//     Windows on a named pipe. Neither can be reached from another computer,
//     and there is no TCP port.
//   - Every connection is checked by the operating system's own identity
//     check before a single byte is read (see transport_*.go): on Linux the
//     caller must be root, the service's own user, or in the "trafficam"
//     group; on Windows the pipe only admits SYSTEM, Administrators and the
//     interactively logged-in user.
//   - It is read-mostly and passive: nothing here can change network traffic.
//   - It runs as a supervised background task. If it fails, capture and
//     scoring carry on.
package localapi

import (
	"time"

	"github.com/Venkatesan7G/trafficam/internal/ramp"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Status is the watcher's health and learning progress.
type Status struct {
	Now         time.Time     `json:"now"`
	Started     time.Time     `json:"started"`
	InstalledAt time.Time     `json:"installed_at"`
	Ramp        ramp.Progress `json:"ramp"`
	Collector   string        `json:"collector"`
	LastFlow    time.Time     `json:"last_flow,omitempty"` // zero = nothing seen yet
	Flows       uint64        `json:"flows"`
	Rows        uint64        `json:"rows"`
	Alerts      uint64        `json:"alerts"` // since this start
	Dropped     uint64        `json:"dropped"`
	Panics      uint64        `json:"panics"`
	Restarts    uint64        `json:"restarts"`
	Unread      int           `json:"unread"` // alerts in state "new"
	// Tamper is the text of <data>/TAMPER-ALERT.txt while that file exists
	// (written by the tamper response; deleted when the user acknowledges it).
	Tamper      string `json:"tamper,omitempty"`
	LatestAlert int64  `json:"latest_id"` // newest alert ID (0 = none)
}

// AlertList is the reply to /v1/alerts and /v1/alerts/wait.
type AlertList struct {
	Alerts []store.Alert `json:"alerts"`
}
