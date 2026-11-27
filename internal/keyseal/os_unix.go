//go:build !windows

package keyseal

import "os"

const isWindows = false

// syncDir flushes a directory entry (the rename) to disk.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
