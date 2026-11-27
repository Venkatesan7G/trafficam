package rules

import (
	"context"
	"errors"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/score"
)

type failing struct{}

func (failing) Name() string { return "failing" }
func (failing) Score(context.Context, []event.Minute) ([]score.Verdict, error) {
	return nil, errors.New("model unavailable")
}
