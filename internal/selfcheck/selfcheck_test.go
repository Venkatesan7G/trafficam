package selfcheck

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/localapi"
	"github.com/Venkatesan7G/trafficam/internal/ramp"
)

func TestRun(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	good := localapi.Status{Now: now, Started: now.Add(-time.Hour), LastFlow: now.Add(-time.Second), Flows: 10, Collector: "etw", Ramp: ramp.At(5 * 24 * time.Hour)}
	rs := Run(context.Background(), Inputs{Now: func() time.Time { return now },
		Status:        func(context.Context) (localapi.Status, error) { return good, nil },
		Notifications: func() error { return nil }, Autostart: func() (bool, error) { return true, nil }})
	if Worst(rs) != Pass {
		t.Fatalf("%+v", rs)
	}

	bad := good
	bad.LastFlow, bad.Tamper = time.Time{}, "Key replaced\nmore"
	rs = Run(context.Background(), Inputs{Now: func() time.Time { return now },
		Status:    func(context.Context) (localapi.Status, error) { return bad, nil },
		Autostart: func() (bool, error) { return false, nil }})
	fails := 0
	for _, r := range rs {
		if r.Level == Fail {
			fails++
		}
	}
	if fails != 2 || Worst(rs) != Fail { // tamper + no capture
		t.Fatalf("%+v", rs)
	}

	rs = Run(context.Background(), Inputs{Status: func(context.Context) (localapi.Status, error) { return localapi.Status{}, errors.New("down") }})
	if len(rs) != 1 || rs[0].Level != Fail {
		t.Fatalf("%+v", rs)
	}
}
