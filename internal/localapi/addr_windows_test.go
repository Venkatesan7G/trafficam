//go:build windows

package localapi

import (
	"fmt"
	"math/rand/v2"
)

// testAddr is a fresh named pipe for one test (pipes are not files).
func testAddr(string) string { return fmt.Sprintf(`\\.\pipe\trafficam-test-%d`, rand.Int64()) }
