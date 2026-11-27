//go:build !windows

package main

import (
	"os/exec"
)

// defaultListsDir is the same data folder the other commands use. Run with
// sudo to change the lists of a watcher that runs as root.
func defaultListsDir() string { return defaultDataDir() }

func defaultEditor() []string {
	for _, e := range []string{"nano", "vi"} {
		if _, err := exec.LookPath(e); err == nil {
			return []string{e}
		}
	}
	return []string{"vi"}
}
