//go:build linux

package main

import (
	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/collector/linuxebpf"
)

// liveCollector returns the real capture source for this OS. On Linux that
// is the eBPF collector. The `live` command (added with the Windows
// collector) calls this; live_windows.go and live_other.go provide the same
// function for other systems.
func liveCollector() (collector.Collector, error) {
	return linuxebpf.New(linuxebpf.Config{}), nil
}
