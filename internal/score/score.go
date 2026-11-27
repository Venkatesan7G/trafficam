// Package score is the seam between the core and the model.
//
// The core never knows how scoring works. It only talks to Scorer. The model
// code (heads A, B, C, being written in a separate thread) implements this
// interface and is plugged in at start-up in cmd/trafficam.
//
// Contract (kept deliberately small so it can stay stable):
//
//   - Score is called once per batch of CLOSED minute rows, oldest first.
//     It returns exactly one Verdict per input row, in the same order.
//   - Score may learn as it goes (the model is passive and self-supervised),
//     so it is allowed to keep state and update itself from the batch.
//   - Score must be fast (it runs on the service's scoring goroutine) and must
//     never touch the network.
//   - Returning an error or panicking is survivable: the service recovers,
//     logs, and treats the batch as unscored. The watcher keeps running.
package score

import (
	"context"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Verdict is the scorer's opinion about one Minute row.
type Verdict struct {
	// Score is 0..1, higher = more unusual for this program on this machine.
	Score float64
	// Alert is true when the scorer decides the user should be told. The
	// scorer owns the threshold (it is self-set from the machine's own history).
	Alert bool
	// Reasons are short human-readable explanations shown in the notification,
	// e.g. "firefox has never contacted this host before".
	Reasons []string
	// Phase lets the UI show the gamified ramp ("Listening", "Settling in",
	// "Watching", "Guarding"). Empty if the scorer does not track phases.
	Phase string
}

// Scorer is implemented by the model.
type Scorer interface {
	Name() string
	Score(ctx context.Context, batch []event.Minute) ([]Verdict, error)
}

// Nop never alerts. It is the default until the real model is plugged in, and
// makes the pipeline testable on its own.
type Nop struct{}

func (Nop) Name() string { return "nop" }

func (Nop) Score(_ context.Context, batch []event.Minute) ([]Verdict, error) {
	return make([]Verdict, len(batch)), nil
}

// Alert is what a Notifier receives: the row plus the verdict.
type Alert struct {
	Minute  event.Minute
	Verdict Verdict
}

// Notifier shows alerts to the user. Desktop toasts are implemented per OS
// later; the core only needs this interface. It must not block for long.
type Notifier interface {
	Notify(a Alert)
}
