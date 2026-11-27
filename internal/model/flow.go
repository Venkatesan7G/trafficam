// Package model is trafficam's learning core: a small self-supervised network
// (heads A and B, trained nightly on the machine's own flows), a frozen
// pretrained prior-risk net (head C), per-program surprise scoring and
// feature-level explanations.
//
// The package has no OS-specific code and no dependency on the rest of
// trafficam. The capture and storage layers hand it Flow values; it hands back
// Verdict values. See docs/model.md.
package model

import "time"

// Proto is the transport protocol of a flow.
type Proto uint8

const (
	TCP Proto = iota
	UDP
)

// Direction says who opened the flow.
type Direction uint8

const (
	Outbound Direction = iota
	Inbound
)

// Flow is one (program, destination, port) contact aggregated over a minute.
// It is the model's only input. Fields map to the feature table in the design
// doc. Program is the free self-supervision label and is never an input.
type Flow struct {
	Time    time.Time // local wall-clock time, used for hour and weekday
	Program string    // program identity, as resolved by the capture layer

	// Categorical inputs.
	Dest    string // registrable domain (eTLD+1) if known, else ASN key
	ASN     uint32
	Parent  string // parent program
	Country string // ISO 3166 alpha-2, "" if unknown
	Port    uint16
	Proto   Proto
	Dir     Direction

	// Numeric inputs.
	BytesOut, BytesIn  float64
	DurationSec        float64
	SendEvents         float64
	IntervalCV         float64 // coefficient of variation of gaps to this destination over 1 h; 0 if fewer than 3 contacts
	Contacts1h         float64 // contacts to this destination in the last hour
	FanOut60s          float64 // distinct hosts this program contacted in 60 s
	FailRate5m         float64 // 0..1
	DNSBeforeConnect   bool
	DNSEntropy, DNSLen float64
	SeenBefore         bool    // this program has used this destination before
	DaysSinceFirstSeen float64 // days since destination first seen on the machine
	OtherPrograms      float64 // other programs using this destination
	Signed             bool
}
