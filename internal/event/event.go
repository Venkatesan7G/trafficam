// Package event defines the data that flows through trafficam.
//
// There are two shapes:
//
//   - Flow:   one raw observation from a platform collector (a connection
//     opened, a DNS answer seen, ...). Collectors produce these.
//   - Minute: many Flows rolled up into one row per minute per
//     (program, protocol, direction, destination, port). This is what gets
//     stored and scored.
//
// Both carry SchemaVersion so old recordings and old databases can still be
// understood after the format changes. Bump the constant when a field is
// added, removed or changes meaning.
//
// Privacy: only metadata is stored (who talked to whom, when, how much).
// Packet payloads are never captured.
package event

import (
	"net/netip"
	"time"
)

// SchemaVersion is the version of the Flow and Minute formats.
const SchemaVersion = 1

// Proto is the transport protocol of a flow.
type Proto string

const (
	TCP   Proto = "tcp"
	UDP   Proto = "udp"
	DNS   Proto = "dns" // a DNS lookup made by a program (query or answer)
	Other Proto = "other"
)

// Direction says who started the conversation.
type Direction string

const (
	Outbound Direction = "out" // this PC connected to someone
	Inbound  Direction = "in"  // someone connected to this PC
)

// Program identifies the program that owns a flow. Collectors fill in as much
// as the OS lets them; empty fields are fine.
type Program struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name"`             // short name, e.g. "firefox"
	Path   string `json:"path,omitempty"`   // full executable path
	Parent string `json:"parent,omitempty"` // parent program name
	Signer string `json:"signer,omitempty"` // code signer (Windows) or package (Linux), if known
}

// Key is the stable identity used to group a program's behaviour over time.
// The path is preferred over the name because names are easy to fake.
func (p Program) Key() string {
	if p.Path != "" {
		return p.Path
	}
	return p.Name
}

// Flow is one raw observation produced by a Collector.
type Flow struct {
	V           int            `json:"v"`
	Time        time.Time      `json:"t"`
	Proto       Proto          `json:"proto"`
	Dir         Direction      `json:"dir"`
	Program     Program        `json:"prog"`
	Local       netip.AddrPort `json:"local"`
	Remote      netip.AddrPort `json:"remote"`
	DNSName     string         `json:"dns,omitempty"` // name the program looked up to reach Remote, or the name queried when Proto==DNS
	BytesIn     uint64         `json:"bin,omitempty"`
	BytesOut    uint64         `json:"bout,omitempty"`
	Packets     uint64         `json:"pkts,omitempty"`
	Established bool           `json:"est,omitempty"` // TCP handshake completed (distinguishes scans from real connections)
}

// Host is the destination as a human would name it: the DNS name if we know
// one (stable across CDN IP churn), otherwise the IP address.
func (f Flow) Host() string {
	if f.DNSName != "" {
		return f.DNSName
	}
	if f.Remote.Addr().IsValid() {
		return f.Remote.Addr().String()
	}
	return ""
}

// Minute is the per-minute rollup stored in the database and handed to the
// scorer. Start is always truncated to a whole minute (UTC).
type Minute struct {
	V           int       `json:"v"`
	Start       time.Time `json:"start"`
	Program     Program   `json:"prog"`
	Proto       Proto     `json:"proto"`
	Dir         Direction `json:"dir"`
	Host        string    `json:"host"`         // DNS name, or IP if no name known
	RemoteIP    string    `json:"ip,omitempty"` // last remote IP seen in this minute
	Port        uint16    `json:"port"`         // remote port
	Flows       uint32    `json:"flows"`        // number of flows merged into this row
	Packets     uint64    `json:"pkts"`
	BytesIn     uint64    `json:"bin"`
	BytesOut    uint64    `json:"bout"`
	FailedCount uint32    `json:"failed,omitempty"` // TCP attempts that never established
}
