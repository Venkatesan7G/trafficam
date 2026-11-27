//go:build !linux && !windows

package main

import "errors"

func setAutostart(bool) error { return errors.New("autostart is only built for Linux and Windows") }
