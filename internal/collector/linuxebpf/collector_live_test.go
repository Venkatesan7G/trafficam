//go:build linux

package linuxebpf

// These tests load the real eBPF program into the running kernel, make
// some traffic from inside the test, and check the flows that come out.
// They need root, so they only run when asked:
//
//	sudo TRAFFICAM_EBPF_TEST=1 go test -run Live -v ./internal/collector/linuxebpf
//
// CI runs them on GitHub's Ubuntu runners (see .github/workflows/ci.yml).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// liveRun starts the collector and returns a function that waits for a
// flow matching want (or fails after a timeout).
func liveRun(t *testing.T) (waitFor func(desc string, want func(event.Flow) bool) event.Flow) {
	t.Helper()
	if os.Getenv("TRAFFICAM_EBPF_TEST") != "1" {
		t.Skip("set TRAFFICAM_EBPF_TEST=1 and run as root to load eBPF for real")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var flows []event.Flow
	c := New(Config{
		Log:             slog.New(slog.NewTextHandler(os.Stderr, nil)),
		IncludeLoopback: true, // the test talks to itself over 127.0.0.1
		SweepEvery:      200 * time.Millisecond,
		UDPIdle:         time.Second,
		TCPReportAfter:  time.Second,
	})
	// done is closed when Run returns; runErr is only read after that.
	// (Closing instead of sending means both the start-up check and the
	// cleanup can wait on it; a send could only be received once, which
	// once made a failed start hang the test.)
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = c.Run(ctx, func(f event.Flow) {
			mu.Lock()
			flows = append(flows, f)
			mu.Unlock()
		})
	}()
	stopped := false
	t.Cleanup(func() {
		cancel()
		<-done
		if runErr != nil && !stopped {
			t.Errorf("Run returned error: %v", runErr)
		}
	})
	time.Sleep(500 * time.Millisecond) // let the hooks attach
	select {
	case <-done:
		stopped = true
		t.Fatalf("collector stopped at start: %v", runErr)
	default:
	}

	return func(desc string, want func(event.Flow) bool) event.Flow {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			for _, f := range flows {
				if want(f) {
					mu.Unlock()
					t.Logf("%s: %+v", desc, f)
					return f
				}
			}
			mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		for _, f := range flows {
			t.Logf("seen: %+v", f)
		}
		t.Fatalf("%s: no matching flow within 10s", desc)
		return event.Flow{}
	}
}

// near: TCP byte counts come from sequence numbers, so the SYN and FIN
// can add up to 2 bytes.
func near(got, want uint64) bool { return got >= want && got <= want+2 }

func isMe(f event.Flow) bool { return f.Program.PID == os.Getpid() }

func TestLiveTCP(t *testing.T) {
	waitFor := liveRun(t)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, c)
		c.Write(make([]byte, 3000))
		c.Close()
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(make([]byte, 1234))
	conn.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, conn)
	conn.Close()

	out := waitFor("outbound TCP", func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.TCP && f.Dir == event.Outbound && f.Remote.Port() == port && f.BytesOut > 0
	})
	if !out.Established || !near(out.BytesOut, 1234) || !near(out.BytesIn, 3000) || out.Duration <= 0 {
		t.Errorf("outbound flow details wrong: %+v", out)
	}
	exe, _ := os.Executable()
	if out.Program.Path != exe {
		t.Errorf("program path = %q, want %q", out.Program.Path, exe)
	}
	in := waitFor("inbound TCP", func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.TCP && f.Dir == event.Inbound && f.Local.Port() == port
	})
	if !near(in.BytesIn, 1234) || !near(in.BytesOut, 3000) {
		t.Errorf("inbound flow bytes wrong: %+v", in)
	}

	// A refused connection is reported as not established.
	l2, _ := net.Listen("tcp4", "127.0.0.1:0")
	closedPort := uint16(l2.Addr().(*net.TCPAddr).Port)
	l2.Close()
	if c, err := net.Dial("tcp4", l2.Addr().String()); err == nil {
		c.Close()
	}
	waitFor("refused TCP", func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.TCP && f.Remote.Port() == closedPort && !f.Established
	})
}

// A connection open longer than TCPReportAfter (1 s here) is reported
// early and again when it closes; the second report is marked Cont so the
// connection is counted once.
func TestLiveLongTCP(t *testing.T) {
	waitFor := liveRun(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	mine := func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.TCP && f.Dir == event.Outbound && f.Remote.Port() == port
	}
	early := waitFor("early report of a long TCP connection", func(f event.Flow) bool { return mine(f) && !f.Cont })
	conn.Write(make([]byte, 500))
	conn.Close()
	last := waitFor("closing report", func(f event.Flow) bool { return mine(f) && f.Cont })
	if !near(last.BytesOut, 500) || early.Duration <= 0 || last.Duration <= 0 {
		t.Errorf("early %+v, last %+v", early, last)
	}
}

func TestLiveUDPAndDNS(t *testing.T) {
	if !probeFentry() {
		t.Skip("this kernel refuses fentry/fexit hooks, so UDP cannot be watched here")
	}
	waitFor := liveRun(t)

	// Plain UDP: 3 datagrams of 100 bytes.
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cl, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		cl.Write(make([]byte, 100))
	}
	cl.Close()
	port := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
	waitFor("outbound UDP", func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.UDP && f.Dir == event.Outbound && f.Remote.Port() == port && f.BytesOut == 300
	})

	// DNS: a tiny fake DNS server on 127.0.0.1:53 answers one name with a
	// documentation address. Then we connect to that address and expect
	// the connection to be labelled with the name.
	dns, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:53 for the fake DNS server: %v", err)
	}
	defer dns.Close()
	answer := netip.MustParseAddr("192.0.2.77")
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := dns.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:n])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 120},
				dnsmessage.AResource{A: answer.As4()})
			msg, _ := b.Finish()
			dns.WriteToUDP(msg, from)
		}
	}()
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("udp4", "127.0.0.1:53")
	}}
	addrs, err := r.LookupNetIP(context.Background(), "ip4", "trafficam-test.example")
	if err != nil || len(addrs) == 0 || addrs[0] != answer {
		t.Fatalf("fake DNS lookup failed: %v %v", addrs, err)
	}
	waitFor("DNS lookup", func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.DNS && f.DNSName == "trafficam-test.example"
	})

	// 192.0.2.0/24 is unroutable, so this connect fails; we only need the
	// attempt, labelled with the name.
	d := net.Dialer{Timeout: time.Second}
	if c, err := d.Dial("tcp4", "192.0.2.77:80"); err == nil {
		c.Close()
	}
	waitFor("TCP labelled with DNS name", func(f event.Flow) bool {
		return isMe(f) && f.Proto == event.TCP && f.Remote.Addr() == answer && f.DNSName == "trafficam-test.example"
	})

	// Many lookups in a row, each from a brand-new socket to the same
	// server. The kernel reuses a closed socket's memory for the next one,
	// which once made about 1 in 15 lookups show up as program "unknown".
	// Every one of them must be ours. (Run last: every answer is the same
	// address, so these names replace the one checked above.)
	const many = 40
	for i := 0; i < many; i++ {
		name := fmt.Sprintf("n%d.trafficam-test.example", i)
		if _, err := r.LookupNetIP(context.Background(), "ip4", name); err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
	}
	for i := 0; i < many; i++ {
		name := fmt.Sprintf("n%d.trafficam-test.example", i)
		f := waitFor("DNS lookup "+name, func(f event.Flow) bool {
			return f.Proto == event.DNS && f.DNSName == name
		})
		if !isMe(f) {
			t.Errorf("lookup %s credited to %+v, want this test (pid %d)", name, f.Program, os.Getpid())
		}
	}
}
