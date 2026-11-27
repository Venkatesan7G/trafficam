//go:build !linux && !windows

package notify

import "errors"

// New returns a notifier that only reports it is unsupported.
func New() Desktop { return none{} }

type none struct{}

func (none) Name() string { return "none" }
func (none) Show(Note) error {
	return errors.New("desktop notifications are only built for Linux and Windows")
}
func (none) Check() error {
	return errors.New("desktop notifications are only built for Linux and Windows")
}
