//go:build windows

package main

import (
	"os"
)

// defaultListsDir is the Windows service's data folder when the service is
// installed (that is where the running watcher reads the lists), otherwise
// the per-user folder used by the other commands.
func defaultListsDir() string {
	if st, err := os.Stat(serviceDataDir()); err == nil && st.IsDir() {
		return serviceDataDir()
	}
	return defaultDataDir()
}

func defaultEditor() []string { return []string{"notepad.exe"} }
