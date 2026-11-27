//go:build windows

package main

import (
	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/collector/etw"
)

// liveCollector is the real capture layer for this OS: ETW on Windows.
func liveCollector() (collector.Collector, error) {
	return &etw.Collector{}, nil
}
