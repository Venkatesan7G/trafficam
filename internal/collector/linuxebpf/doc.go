// Package linuxebpf is trafficam's Linux collector. It watches every TCP
// and UDP connection and every DNS lookup on the machine with eBPF, and
// reports them as event.Flow values through the collector.Collector
// interface.
//
// It is passive: it only uses tracing hooks and a read-only packet socket,
// which cannot change, delay or drop traffic. If trafficam crashes, the
// kernel removes the hooks automatically and networking is unaffected.
//
// Needs Linux 6.1 or newer with BTF (/sys/kernel/btf/vmlinux, present on
// all mainstream distros) and root (or CAP_BPF + CAP_PERFMON + CAP_NET_RAW).
//
// See docs/LINUX.md for how it works and how to test it.
package linuxebpf
