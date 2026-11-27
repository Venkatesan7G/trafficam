//go:build !windows

package localapi

import "path/filepath"

// testAddr is a socket inside the test's own folder.
func testAddr(dir string) string { return filepath.Join(dir, "api.sock") }
