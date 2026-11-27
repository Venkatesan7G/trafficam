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
// v2 added Minute.ASN, Country and DurationMs, and Flow.Duration.
// v3 added Program.Service.
// v4 added Flow.Cont.
const SchemaVersion = 4

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
	// Service is the OS service this process runs, if any: the Windows
	// service name(s) hosted in the process (e.g. "Dnscache"), or the systemd
	// unit on Linux. Several Windows services share one svchost.exe, so
	// without this they would all look like the same program.
	Service string `json:"svc,omitempty"`
}

// Key is the stable identity used to group a program's behaviour over time.
// The path is preferred over the name because names are easy to fake.
// When the process hosts a service, the service name is added so that, say,
// Dnscache and wuauserv inside svchost.exe get separate baselines.
func (p Program) Key() string {
	k := p.Name
	if p.Path != "" {
		k = p.Path
	}
	if p.Service != "" {
		k += "|" + p.Service
	}
	return k
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
	Duration    time.Duration  `json:"dur,omitempty"` // how long the connection lasted, if the collector knows
	Established bool           `json:"est,omitempty"` // TCP handshake completed (distinguishes scans from real connections)
	// Cont marks a later report of a connection that was already reported
	// once (a long download reported minute by minute, or the closing totals
	// of a connection first reported while still open). Its bytes, packets
	// and Duration cover only the time since the previous report, so they can
	// simply be added up, but it must not be counted as another connection.
	Cont bool `json:"cont,omitempty"`
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
	ASN         uint32    `json:"asn,omitempty"`    // network owner of RemoteIP, from the offline database (0 = unknown)
	Country     string    `json:"cc,omitempty"`     // ISO country code of RemoteIP (empty = unknown)
	DurationMs  uint64    `json:"dur_ms,omitempty"` // total connection time across merged flows
	FailedCount uint32    `json:"failed,omitempty"` // TCP attempts that never established
}
