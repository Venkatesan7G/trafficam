//go:build windows && (amd64 || arm64)

package etw

// These tests run real ETW capture. They need administrator rights, which
// GitHub's Windows runners have. On a normal (non-admin) shell they skip,
// unless TRAFFICAM_REQUIRE_ETW=1 is set (CI sets it so a skip can't hide a
// failure).
//
// TestLiveCapture is also the proof for the two questions we had to answer
// before relying on ETW:
//
//  1. Does the DNS-Client event carry the PID of the program that asked?
//     -> we resolve a name in this test process and check the DNS flow's PID.
//  2. Can we get per-connection byte counts?
//     -> we send/receive exact byte counts and check the flow's totals.
//
// Run it on your own PC from an *administrator* terminal:
//
//	go test -v -run LiveCapture ./internal/collector/etw/

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func TestStructSizes(t *testing.T) {
	sizes := map[string][2]uintptr{
		"EVENT_TRACE_PROPERTIES": {unsafe.Sizeof(eventTraceProperties{}), 120},
		"EVENT_HEADER":           {unsafe.Sizeof(eventHeader{}), 80},
		"EVENT_RECORD":           {unsafe.Sizeof(eventRecord{}), 112},
		"EVENT_TRACE":            {unsafe.Sizeof(eventTrace{}), 88},
		"TRACE_LOGFILE_HEADER":   {unsafe.Sizeof(traceLogfileHeader{}), 280},
		"EVENT_TRACE_LOGFILEW":   {unsafe.Sizeof(eventTraceLogfile{}), 448},
		"WINTRUST_CATALOG_INFO":  {unsafe.Sizeof(wintrustCatalogInfo{}), 72},
	}
	for name, s := range sizes {
		if s[0] != s[1] {
			t.Errorf("%s is %d bytes, Windows expects %d", name, s[0], s[1])
		}
	}
}

func TestSignerOfWindowsBinary(t *testing.T) {
	// svchost.exe is catalog-signed, so this exercises the catalog path.
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "svchost.exe")
	s := verifySigner(p)
	t.Logf("signer of %s: %q", p, s)
	if !strings.Contains(s, "Microsoft") {
		t.Fatalf("expected a Microsoft signer, got %q", s)
	}
	exe, _ := os.Executable()
	t.Logf("signer of this test binary: %q", verifySigner(exe))
	if got := verifySigner(exe); got != "unsigned" {
		t.Errorf("test binary should be unsigned, got %q", got)
	}
}

func TestServiceNames(t *testing.T) {
	m, err := runningServices()
	if err != nil {
		t.Fatal(err)
	}
	pi := newProcInfo()
	found := false
	for pid, names := range m {
		if strings.Contains(names, "Dnscache") {
			p := pi.lookup(pid)
			t.Logf("Dnscache runs in pid %d: %+v", pid, p)
			if !strings.EqualFold(p.Name, "svchost.exe") || p.Service == "" || !strings.Contains(p.Signer, "Microsoft") {
				t.Errorf("unexpected program for Dnscache: %+v", p)
			}
			found = true
		}
	}
	if !found {
		t.Error("Dnscache service not found among running services")
	}
}

// resolve looks a name up through the Windows DNS client (dnsapi), the path
// every normal Windows program uses, and returns its IPv4 answers.
func resolve(name string) ([]netip.Addr, error) {
	n, _ := windows.UTF16PtrFromString(name)
	hints := windows.AddrinfoW{Family: windows.AF_INET, Socktype: windows.SOCK_STREAM}
	var res *windows.AddrinfoW
	if err := windows.GetAddrInfoW(n, nil, &hints, &res); err != nil {
		return nil, err
	}
	defer windows.FreeAddrInfoW(res)
	var out []netip.Addr
	for r := res; r != nil; r = r.Next {
		if r.Family == windows.AF_INET {
			ap := *(*unsafe.Pointer)(unsafe.Pointer(&r.Addr)) // vet-friendly uintptr -> pointer
			sa := (*windows.RawSockaddrInet4)(ap)
			out = append(out, netip.AddrFrom4(sa.Addr))
		}
	}
	return out, nil
}

func TestLiveCapture(t *testing.T) {
	var mu sync.Mutex
	var flows []event.Flow
	c := &Collector{
		SessionName:  "trafficam-test",
		KeepLoopback: true,
		StatsEvery:   -1,
		checkLayout:  true,
		trackerCfg:   trackerConfig{IdleTCP: 2 * time.Second, IdleUDP: 2 * time.Second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- c.Run(ctx, func(f event.Flow) { mu.Lock(); flows = append(flows, f); mu.Unlock() })
	}()
	select {
	case err := <-runErr:
		if errors.Is(err, errAccessDenied) && os.Getenv("TRAFFICAM_REQUIRE_ETW") != "1" {
			t.Skip("needs an administrator terminal")
		}
		t.Fatalf("collector stopped at once: %v", err)
	case <-time.After(3 * time.Second): // give ETW a moment to start delivering
	}
	me := uint32(os.Getpid())

	// 1. DNS lookup from this process.
	ips, dnsErr := resolve("example.com")
	t.Logf("example.com -> %v (err %v)", ips, dnsErr)
	resolve(fmt.Sprintf("trafficam-nx-%d.example.com", time.Now().UnixNano())) // NXDOMAIN

	// 2. Loopback TCP with exact byte counts.
	const up, down = 123456, 7890
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		io.CopyN(io.Discard, s, up)
		s.Write(make([]byte, down))
		s.Close()
	}()
	cl, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientLocal := netip.MustParseAddrPort(cl.LocalAddr().String())
	cl.Write(make([]byte, up))
	io.Copy(io.Discard, cl)
	cl.Close()
	ln.Close()

	// 3. Loopback UDP: 3 datagrams of 100 bytes.
	uc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	us, _ := net.Dial("udp4", uc.LocalAddr().String())
	udpLocal := netip.MustParseAddrPort(us.LocalAddr().String())
	for i := 0; i < 3; i++ {
		us.Write(make([]byte, 100))
	}
	us.Close()
	uc.Close()

	// 4. External HTTP to the address we just resolved.
	var extLocal netip.AddrPort
	var extIn, extOut int64
	if len(ips) > 0 {
		if conn, err := net.DialTimeout("tcp4", netip.AddrPortFrom(ips[0], 80).String(), 5*time.Second); err == nil {
			extLocal = netip.MustParseAddrPort(conn.LocalAddr().String())
			req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
			n, _ := conn.Write([]byte(req))
			extOut = int64(n)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			extIn, _ = io.Copy(io.Discard, conn)
			conn.Close()
		} else {
			t.Logf("external connection failed (no internet on this machine?): %v", err)
		}
	}

	// 5. Another program: curl.exe (ships with Windows, catalog-signed).
	var curlPID uint32
	if curl, err := exec.LookPath("curl.exe"); err == nil {
		cmd := exec.Command(curl, "-s", "-o", "NUL", "--max-time", "5", "http://example.com/")
		if err := cmd.Start(); err == nil {
			curlPID = uint32(cmd.Process.Pid)
			cmd.Wait()
		}
	}

	// 6. Failed connections: a closed local port, and an address that never answers.
	if l, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
		addr := l.Addr().String()
		l.Close()
		_, err := net.DialTimeout("tcp4", addr, 3*time.Second)
		t.Logf("dial closed port %s: %v", addr, err)
	}
	_, err = net.DialTimeout("tcp4", "10.255.255.1:81", 4*time.Second)
	t.Logf("dial black-hole 10.255.255.1:81: %v", err)

	time.Sleep(8 * time.Second) // let idle timers (2 s) and a sweep (5 s) fire
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run returned %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	t.Logf("stats: events=%d flows=%d queue_dropped=%d layout_checks=%d",
		c.Stats.Events.Load(), c.Stats.Flows.Load(), c.Stats.QueueDropped.Load(), c.Stats.LayoutChecks.Load())
	for _, f := range flows {
		if uint32(f.Program.PID) == me || (curlPID != 0 && uint32(f.Program.PID) == curlPID) {
			t.Logf("flow: %s %s %v -> %v dns=%q in=%d out=%d pkts=%d est=%v dur=%v prog=%+v",
				f.Proto, f.Dir, f.Local, f.Remote, f.DNSName, f.BytesIn, f.BytesOut, f.Packets, f.Established, f.Duration, f.Program)
		}
	}

	// Layout check: our parse of every network event matched TDH.
	if bad := c.layoutBad.Load(); bad != nil {
		t.Errorf("Kernel-Network layout mismatch: %v", bad)
	}
	if c.Stats.LayoutChecks.Load() == 0 {
		t.Error("no Kernel-Network events were seen at all")
	}

	sum := func(match func(event.Flow) bool) (in, out uint64, n int, f0 event.Flow) {
		for _, f := range flows {
			if match(f) {
				in += f.BytesIn
				out += f.BytesOut
				if n == 0 {
					f0 = f
				}
				n++
			}
		}
		return
	}

	// Q1: DNS flows carry the asking process.
	if dnsErr == nil {
		_, _, n, f := sum(func(f event.Flow) bool { return f.Proto == event.DNS && f.DNSName == "example.com" })
		switch {
		case n == 0:
			t.Error("Q1: no DNS flow for example.com")
		case uint32(f.Program.PID) != me:
			t.Errorf("Q1: DNS flow PID is %d (%s), want this process %d", f.Program.PID, f.Program.Name, me)
		default:
			t.Logf("Q1 PASS: DNS lookup attributed to pid %d %s", f.Program.PID, f.Program.Path)
		}
		_, _, n, f = sum(func(f event.Flow) bool {
			return f.Proto == event.DNS && strings.HasPrefix(f.DNSName, "trafficam-nx-")
		})
		if n == 0 || f.Established {
			t.Errorf("failed lookup should be a DNS flow with Established=false (got %d flows, %+v)", n, f)
		}
	}

	// Q2: per-connection byte counts, exact.
	in, out, n, f := sum(func(f event.Flow) bool {
		return f.Proto == event.TCP && f.Local == clientLocal && uint32(f.Program.PID) == me
	})
	if n == 0 {
		t.Error("Q2: no flow for the loopback TCP client")
	} else {
		if in != down || out != up {
			t.Errorf("Q2: loopback TCP bytes in/out = %d/%d, want %d/%d", in, out, down, up)
		} else {
			t.Logf("Q2 PASS: loopback TCP bytes in/out = %d/%d exactly", in, out)
		}
		if f.Dir != event.Outbound || !f.Established {
			t.Errorf("loopback client flow should be outbound and established: %+v", f)
		}
		exe, _ := os.Executable()
		if !strings.EqualFold(f.Program.Path, exe) {
			t.Errorf("program path %q, want %q", f.Program.Path, exe)
		}
	}
	in, out, n, _ = sum(func(f event.Flow) bool { return f.Proto == event.UDP && f.Local == udpLocal })
	if n == 0 || out != 300 {
		t.Errorf("UDP: want 300 bytes out, got %d in %d flows", out, n)
	}
	if extLocal.IsValid() {
		in, out, n, f = sum(func(f event.Flow) bool { return f.Proto == event.TCP && f.Local == extLocal })
		if n == 0 {
			t.Error("no flow for the external HTTP connection")
		} else {
			if in != uint64(extIn) || out != uint64(extOut) {
				t.Errorf("external bytes in/out = %d/%d, want %d/%d", in, out, extIn, extOut)
			}
			if f.DNSName != "example.com" || f.Remote.Port() != 80 {
				t.Errorf("external flow should be example.com:80, got %q %v", f.DNSName, f.Remote)
			}
		}
	}
	if curlPID != 0 {
		_, _, n, f = sum(func(f event.Flow) bool { return uint32(f.Program.PID) == curlPID && f.Proto == event.TCP })
		if n == 0 {
			t.Log("no TCP flow seen for curl.exe")
		} else {
			t.Logf("curl.exe flow: dns=%q parent=%q signer=%q", f.DNSName, f.Program.Parent, f.Program.Signer)
			if !strings.Contains(f.Program.Signer, "Microsoft") {
				t.Errorf("curl.exe signer %q, want Microsoft", f.Program.Signer)
			}
			exe, _ := os.Executable()
			if !strings.EqualFold(f.Program.Parent, filepath.Base(exe)) {
				t.Errorf("curl.exe parent %q, want %q", f.Program.Parent, filepath.Base(exe))
			}
		}
	}
}
