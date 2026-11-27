//go:build !windows

package main

import (
	"fmt"
	"runtime"

	"github.com/Venkatesan7G/trafficam/internal/collector"
)

// liveCollector: no real capture layer for this OS yet. Windows has
// live_windows.go (ETW). When the Linux eBPF collector lands with its own
// live_linux.go, this file's build line becomes "!windows && !linux".
func liveCollector() (collector.Collector, error) {
	return nil, fmt.Errorf("live capture is not supported on %s yet", runtime.GOOS)
}
