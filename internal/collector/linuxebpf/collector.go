//go:build linux

package linuxebpf

// collector.go is the user-space half of the Linux collector. It loads the
// eBPF program (bpf/trafficam.bpf.c), reads what it reports, adds process
// details from /proc, and hands finished event.Flow values to the core.
//
// Three goroutines do the work:
//
//	readEvents  - reads TCP open/close and "new UDP peer" events from the
//	              kernel's ring buffer
//	sweepLoop   - every few seconds: reports UDP counters, and reports TCP
//	              connections that have been open for a while
//	dnsLoop     - sniffs DNS packets (see dns.go)
//
// When Run returns, every eBPF hook is detached and every map freed. The
// kernel also does this by itself if the process is killed or crashes, so
// a trafficam crash cannot leave anything behind in the network stack.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// MinKernel is the oldest kernel this collector supports: 6.1, the first
// long-term-support kernel that has everything we use (ring buffer 5.8,
// fentry/fexit on arm64 6.0, bpf_get_func_ret 5.17).
var MinKernel = [2]int{6, 1}

// Event kinds; must match the enum in bpf/trafficam.bpf.c.
const (
	evTCPOpen  = 1
	evTCPClose = 2
	evUDPOpen  = 3

	dirOut = 1
	dirIn  = 2
)

// Config tunes the collector. The zero value is what you want normally.
type Config struct {
	Log *slog.Logger // default slog.Default()

	// IncludeLoopback reports connections from this PC to itself
	// (127.0.0.1, ::1). Off by default: that is local plumbing, not network
	// traffic, and would only add noise.
	IncludeLoopback bool

	// TCPReportAfter: a TCP connection still open after this long is
	// reported straight away (without byte counts), so a new long-lived
	// connection is noticed in seconds rather than when it closes. Its
	// totals follow as a second flow when it closes. Default 30s.
	TCPReportAfter time.Duration
	// UDPIdle: a UDP peer quiet for this long is considered finished.
	// Default 30s.
	UDPIdle time.Duration
	// UDPReportEvery: how often an active UDP peer reports its counters.
	// Default 60s.
	UDPReportEvery time.Duration
	// SweepEvery: how often counters are read. Default 5s.
	SweepEvery time.Duration

	// DisableDNS turns off the DNS packet reader. Connections are then
	// reported by IP only.
	DisableDNS bool
}

// Collector implements collector.Collector on Linux with eBPF.
type Collector struct {
	cfg Config
}

// New returns a Linux eBPF collector. Nothing is loaded until Run.
func New(cfg Config) *Collector {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.TCPReportAfter, 30*time.Second)
	def(&cfg.UDPIdle, 30*time.Second)
	def(&cfg.UDPReportEvery, time.Minute)
	def(&cfg.SweepEvery, 5*time.Second)
	return &Collector{cfg: cfg}
}

func (c *Collector) Name() string { return "linux-ebpf" }

// hook says where one eBPF program attaches. Required hooks must work or
// Run fails; optional ones only log a warning (e.g. a kernel built without
// IPv6 has no udpv6_* functions).
type hook struct {
	prog     string
	required bool
}

var hooks = []hook{
	{"on_tcp_state", true},
	{"on_tcp_sendmsg", false},
	{"on_tcp_recvmsg", false},
	{"on_udp_sendmsg", true},
	{"on_udp_recvmsg", true},
	{"on_udpv6_sendmsg", false},
	{"on_udpv6_recvmsg", false},
}

// Run loads the eBPF program and reports flows until ctx is cancelled.
func (c *Collector) Run(ctx context.Context, emit func(event.Flow)) error {
	log := c.cfg.Log
	if err := checkKernel(); err != nil {
		return err
	}
	// Kernels before 5.11 charged eBPF memory to a "locked memory" limit.
	// Harmless no-op on the kernels we support, kept for safety.
	_ = rlimit.RemoveMemlock()

	spec, err := loadTrafficam()
	if err != nil {
		return fmt.Errorf("read embedded eBPF program: %w", err)
	}
	// fentry/fexit hooks (all UDP accounting) need the kernel's BPF
	// trampolines. Every mainstream distro kernel has them, but some
	// locked-down or virtualised kernels refuse them. Then we keep running
	// with TCP and DNS only, and say so loudly, rather than seeing nothing.
	fentryOK := probeFentry()
	if !fentryOK {
		log.Error("this kernel does not allow fentry/fexit eBPF hooks: UDP traffic will NOT be seen, " +
			"and DNS lookups cannot be tied to programs. TCP is still watched.")
	}
	for _, h := range hooks {
		ps := spec.Programs[h.prog]
		if ps == nil {
			continue
		}
		isFentry := ps.AttachType == ebpf.AttachTraceFEntry || ps.AttachType == ebpf.AttachTraceFExit
		switch {
		case isFentry && !fentryOK:
			delete(spec.Programs, h.prog)
		case !h.required && !kernelHasFunc(ps.AttachTo):
			// e.g. a kernel built without IPv6 has no udpv6_* functions.
			log.Warn("kernel function missing, skipping hook", "hook", h.prog, "func", ps.AttachTo)
			delete(spec.Programs, h.prog)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("kernel rejected the eBPF program: %+v", ve)
		}
		return fmt.Errorf("load eBPF program (are you root? needs CAP_BPF and CAP_PERFMON): %w", err)
	}
	defer coll.Close()

	for _, h := range hooks {
		p := coll.Programs[h.prog]
		if p == nil {
			continue
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			if h.required {
				return fmt.Errorf("attach %s: %w", h.prog, err)
			}
			log.Warn("could not attach optional hook", "hook", h.prog, "err", err)
			continue
		}
		defer l.Close()
	}

	// Tell the kernel side about servers that were already listening.
	for port, f := range listenerOwners("/proc") {
		_ = coll.Maps["listeners"].Update(port, toOwner(f), ebpf.UpdateNoExist)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()

	t := newTracker(c.cfg, emit)
	t.udpFlows = coll.Maps["udp_flows"]
	t.udpOwner = coll.Maps["udp_owner"]
	t.conns = coll.Maps["conns"]

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 1)

	if !c.cfg.DisableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := t.dnsLoop(ctx); err != nil {
				// Not fatal: we still see every connection, just without names.
				log.Warn("DNS reader stopped; names will be missing", "err", err)
				t.dnsActive.Store(false)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.sweepLoop(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := t.readEvents(rd); err != nil && ctx.Err() == nil {
			select {
			case errc <- err:
			default:
			}
			cancel()
		}
	}()

	log.Info("linux eBPF collector running")
	<-ctx.Done()
	rd.Close() // unblocks readEvents
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return nil // normal shutdown
	}
}

// readEvents decodes ring buffer records until the reader is closed.
func (t *tracker) readEvents(rd *ringbuf.Reader) error {
	var ev trafficamEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			continue // malformed record; should never happen
		}
		t.handleEvent(&ev)
	}
}

// checkKernel fails early, with a clear message, on kernels we do not support.
func checkKernel() error {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return err
	}
	rel := unix.ByteSliceToString(u.Release[:])
	maj, min, ok := parseKernelVersion(rel)
	if !ok {
		return fmt.Errorf("cannot parse kernel version %q", rel)
	}
	if maj < MinKernel[0] || (maj == MinKernel[0] && min < MinKernel[1]) {
		return fmt.Errorf("kernel %s is too old: trafficam needs Linux %d.%d or newer", rel, MinKernel[0], MinKernel[1])
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("kernel has no BTF type info (/sys/kernel/btf/vmlinux); it must be built with CONFIG_DEBUG_INFO_BTF=y")
	}
	return nil
}

// parseKernelVersion reads "6.8.0-45-generic" as (6, 8).
func parseKernelVersion(rel string) (major, minor int, ok bool) {
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minDigits := parts[1]
	for i, r := range minDigits {
		if r < '0' || r > '9' {
			minDigits = minDigits[:i]
			break
		}
	}
	minor, err2 := strconv.Atoi(minDigits)
	return major, minor, err1 == nil && err2 == nil
}

// probeFentry loads (and immediately frees) a do-nothing fentry program to
// find out whether this kernel allows fentry/fexit hooks.
func probeFentry() bool {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "tcp_sendmsg",
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		return false
	}
	p.Close()
	return true
}

// kernelHasFunc reports whether the running kernel has a function named fn
// (according to its BTF type info).
func kernelHasFunc(fn string) bool {
	if fn == "" {
		return true
	}
	ks, err := kernelSpec()
	if err != nil {
		return true // cannot tell; let the loader decide
	}
	_, err = ks.AnyTypeByName(fn)
	return err == nil
}

// boottimeNow is the kernel clock our eBPF timestamps use. Unlike the
// plain monotonic clock it keeps counting during suspend.
func boottimeNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Nano())
}

// toAddr converts a kernel address field to netip. IPv4-mapped IPv6
// addresses (::ffff:1.2.3.4, used by dual-stack sockets) become plain IPv4.
func toAddr(family uint8, b [16]uint8) netip.Addr {
	if family == unix.AF_INET {
		return netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrFrom16(b).Unmap()
}
