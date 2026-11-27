//go:build linux

// Command ebpfcheck runs the Linux eBPF collector on its own and prints
// every flow it sees as one JSON line. It stores nothing. Use it to check
// that capture works on your machine before running the full trafficam.
//
//	sudo ./ebpfcheck              # run until Ctrl+C
//	sudo ./ebpfcheck -for 30s     # run for 30 seconds, then print a summary
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/collector/linuxebpf"
	"github.com/Venkatesan7G/trafficam/internal/event"
)

func main() {
	dur := flag.Duration("for", 0, "stop after this long (0 = until Ctrl+C)")
	loop := flag.Bool("loopback", false, "also show connections from this PC to itself")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := linuxebpf.New(linuxebpf.Config{Log: log, IncludeLoopback: *loop})
	enc := json.NewEncoder(os.Stdout)
	counts := map[event.Proto]int{}
	err := c.Run(ctx, func(f event.Flow) {
		counts[f.Proto]++
		_ = enc.Encode(f)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "summary after %s: tcp=%d udp=%d dns=%d\n",
		time.Duration(0)+*dur, counts[event.TCP], counts[event.UDP], counts[event.DNS])
}
