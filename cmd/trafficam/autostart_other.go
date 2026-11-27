//go:build !linux && !windows

package main

import (
	"errors"
	"os/exec"
)

func setAutostart(bool) error { return errors.New("autostart is only built for Linux and Windows") }
func autostartEnabled() (bool, error) {
	return false, errors.New("autostart is only built for Linux and Windows")
}
func openBrowser(u string) error { return exec.Command("open", u).Start() }

const accessHint = ""
