// Package collector defines how traffic observations enter trafficam.
//
// THIS INTERFACE IS THE STABLE CONTRACT between the shared core and the
// platform-specific capture code:
//
//	Linux:   eBPF (separate thread)  -> implements Collector
//	Windows: ETW  (separate thread)  -> implements Collector
//	Testing: Replay / Synthetic      -> implemented in this package
//
// Rules every collector must follow:
//
//  1. PASSIVE ONLY. Observe, never alter, delay, block or redirect traffic.
//     No drivers, no packet-filter hooks, no proxies.
//  2. emit() never blocks. The core drops flows when overloaded rather than
//     slowing the collector down, so capture can never stall networking.
//  3. Run returns when ctx is cancelled (nil error) or on an unrecoverable
//     failure (non-nil error). The service restarts it with backoff.
//  4. Fill Flow.V with event.SchemaVersion and Flow.Time with the real event
//     time. Everything else is best effort.
package collector

import (
	"context"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Collector produces Flows until its context is cancelled.
type Collector interface {
	// Name is a short label for logs, e.g. "linux-ebpf".
	Name() string
	// Run captures traffic and calls emit for every flow observed.
	// It blocks until ctx is done or a fatal error occurs.
	Run(ctx context.Context, emit func(event.Flow)) error
}
