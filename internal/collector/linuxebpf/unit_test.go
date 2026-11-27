//go:build linux

package linuxebpf

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/dns/dnsmessage"
)

// buildDNS makes a DNS message; answers non-empty means a response.
func buildDNS(t *testing.T, name string, answers ...netip.Addr) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: len(answers) > 0})
	b.EnableCompression()
	n := dnsmessage.MustNewName(name)
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	// A CNAME first, like CDNs do, to check we skip it correctly.
	if len(answers) > 0 {
		_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 600},
			dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.cdn.example.")})
	}
	for _, a := range answers {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("edge.cdn.example."), Class: dnsmessage.ClassINET, TTL: 300}
		if a.Is4() {
			_ = b.AResource(h, dnsmessage.AResource{A: a.As4()})
		} else {
			_ = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// ipv4UDP wraps payload in minimal IPv4 + UDP headers.
func ipv4UDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[9] = 17
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	p[20], p[21] = byte(sport>>8), byte(sport)
	p[22], p[23] = byte(dport>>8), byte(dport)
	copy(p[28:], payload)
	return p
}

func ipv6UDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	p := make([]byte, 48+len(payload))
	p[0] = 0x60
	p[6] = 17
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	p[40], p[41] = byte(sport>>8), byte(sport)
	p[42], p[43] = byte(dport>>8), byte(dport)
	copy(p[48:], payload)
	return p
}

var (
	me     = netip.MustParseAddr("192.168.1.10")
	dnsSrv = netip.MustParseAddr("1.1.1.1")
)

func TestParseDNSQueryAndAnswer(t *testing.T) {
	q, ok := parseDNSPacket(ipv4UDP(me, dnsSrv, 40000, 53, buildDNS(t, "Example.ORG.")))
	if !ok || q.Response || q.Name != "example.org" || q.Src.Port() != 40000 || q.Dst.Addr() != dnsSrv {
		t.Fatalf("query parsed wrong: %+v ok=%v", q, ok)
	}
	a4, a6 := netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2606:2800::1")
	r, ok := parseDNSPacket(ipv4UDP(dnsSrv, me, 53, 40000, buildDNS(t, "example.org.", a4, a6)))
	if !ok || !r.Response || r.Name != "example.org" || len(r.Answers) != 2 || r.Answers[0] != a4 || r.Answers[1] != a6 {
		t.Fatalf("answer parsed wrong: %+v ok=%v", r, ok)
	}
	if r.TTL != 300*time.Second {
		t.Fatalf("TTL = %v, want 300s (min over A/AAAA records)", r.TTL)
	}
	v6, ok := parseDNSPacket(ipv6UDP(netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:4860:4860::8888"), 5000, 53, buildDNS(t, "ipv6.example.")))
	if !ok || v6.Name != "ipv6.example" {
		t.Fatalf("ipv6 query parsed wrong: %+v", v6)
	}
}

func TestParseDNSRejectsJunk(t *testing.T) {
	for _, p := range [][]byte{nil, {0x45}, make([]byte, 27), ipv4UDP(me, dnsSrv, 1, 53, []byte{1, 2, 3})} {
		if _, ok := parseDNSPacket(p); ok {
			t.Errorf("accepted junk %x", p)
		}
	}
}

func FuzzParseDNSPacket(f *testing.F) {
	f.Add(ipv4UDP(me, dnsSrv, 40000, 53, []byte("not dns")))
	f.Fuzz(func(t *testing.T, b []byte) { parseDNSPacket(b) }) // must not panic
}

// The kernel runs dnsFilter on every packet; here we run it in x/net's
// BPF emulator to check its jump offsets.
func TestDNSFilter(t *testing.T) {
	raw, err := dnsFilter()
	if err != nil {
		t.Fatal(err)
	}
	insns, _ := bpf.Disassemble(raw)
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatal(err)
	}
	q := buildDNS(t, "x.example.")
	v6a, v6b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	tcp := ipv4UDP(me, dnsSrv, 40000, 53, q)
	tcp[9] = 6
	frag := ipv4UDP(me, dnsSrv, 40000, 53, q)
	frag[7] = 1 // fragment offset 8: no UDP header in this packet
	cases := []struct {
		name string
		pkt  []byte
		keep bool
	}{
		{"v4 query", ipv4UDP(me, dnsSrv, 40000, 53, q), true},
		{"v4 answer", ipv4UDP(dnsSrv, me, 53, 40000, q), true},
		{"v4 other udp", ipv4UDP(me, dnsSrv, 40000, 443, q), false},
		{"v4 tcp port 53", tcp, false},
		{"v4 later fragment", frag, false},
		{"v6 query", ipv6UDP(v6a, v6b, 40000, 53, q), true},
		{"v6 answer", ipv6UDP(v6b, v6a, 53, 40000, q), true},
		{"v6 other udp", ipv6UDP(v6a, v6b, 40000, 123, q), false},
		{"not ip", append([]byte{0x00}, q...), false},
	}
	for _, c := range cases {
		n, err := vm.Run(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (n > 0) != c.keep {
			t.Errorf("%s: kept=%v, want %v", c.name, n > 0, c.keep)
		}
	}
}

func TestNameCache(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newNameCache(10)
	c.now = func() time.Time { return now }
	ip := netip.MustParseAddr("93.184.216.34")
	c.Put(100, ip, "a.example", 10*time.Second) // clamped up to 1 min
	c.Put(200, ip, "b.example", time.Hour)
	if got := c.Lookup(100, ip); got != "a.example" {
		t.Errorf("per-process name: got %q", got)
	}
	if got := c.Lookup(999, netip.MustParseAddr("::ffff:93.184.216.34")); got != "b.example" {
		t.Errorf("fallback to machine-wide name (and v4-mapped address): got %q", got)
	}
	now = now.Add(2 * time.Minute)
	if got := c.Lookup(100, ip); got != "b.example" {
		t.Errorf("expired per-process entry should fall back: got %q", got)
	}
	now = now.Add(2 * time.Hour)
	if got := c.Lookup(100, ip); got != "" {
		t.Errorf("everything expired: got %q", got)
	}
}

func TestUnitFromCgroup(t *testing.T) {
	cases := map[string]string{
		"/system.slice/nginx.service":                                                          "nginx.service",
		"/system.slice/system-getty.slice/getty@tty1.service":                                  "getty@tty1.service",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/pipewire.service":             "pipewire.service",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox-1234.scope": "",
		"/user.slice/user-1000.slice/session-2.scope":                                          "",
		"/user.slice/user-1000.slice/user@1000.service/init.scope":                             "",
		"/system.slice/docker-0123abcd.scope":                                                  "",
		"/":                                                                                    "",
		"":                                                                                     "",
	}
	for in, want := range cases {
		if got := unitFromCgroup(in); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeProc builds a tiny /proc tree in a temp dir.
func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(pid, exe, stat, cgroup string) {
		d := filepath.Join(root, pid)
		os.MkdirAll(filepath.Join(d, "fd"), 0o755)
		if exe != "" {
			os.Symlink(exe, filepath.Join(d, "exe"))
		}
		os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
		os.WriteFile(filepath.Join(d, "cgroup"), []byte(cgroup), 0o644)
	}
	mk("1", "/usr/lib/systemd/systemd", "1 (systemd) S 0 1 1", "0::/init.scope\n")
	mk("42", "/usr/sbin/nginx (deleted)", "42 (nginx) S 1 42 42", "0::/system.slice/nginx.service\n")
	mk("77", "/usr/bin/weird", "77 (we ird) pro)g) S 1 77", "12:cpu:/x\n0::/user.slice/user-1000.slice/session-2.scope\n")
	os.Symlink("socket:[5555]", filepath.Join(root, "42", "fd", "6"))
	os.Symlink("/dev/null", filepath.Join(root, "42", "fd", "0"))
	os.MkdirAll(filepath.Join(root, "net"), 0o755)
	os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5555 1 0 100 0 0 10 0\n"+
			"   1: 0100007F:9C40 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 6666 1 0 20 4 30 10 -1\n"), 0o644)
	return root
}

func TestProcResolver(t *testing.T) {
	r := newProcResolver(fakeProc(t), "")
	got := r.Resolve(procFacts{PID: 42, PPID: 1, Comm: "nginx", PComm: "systemd"})
	want := procInfo{Name: "nginx", Path: "/usr/sbin/nginx", Parent: "systemd", Unit: "nginx.service"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// A process that already exited: fall back to what the kernel captured.
	gone := r.Resolve(procFacts{PID: 9999, PPID: 1, Comm: "curl", PComm: "bash"})
	if gone.Name != "curl" || gone.Path != "" || gone.Parent != "systemd" {
		t.Errorf("exited process: got %+v", gone)
	}
}

func TestListenerOwners(t *testing.T) {
	got := listenerOwners(fakeProc(t))
	f, ok := got[80]
	if !ok || f.PID != 42 || f.Comm != "nginx" || f.PPID != 1 || f.PComm != "systemd" {
		t.Fatalf("listener on :80: got %+v (all: %v)", f, got)
	}
	if len(got) != 1 {
		t.Errorf("only LISTEN sockets should be returned, got %v", got)
	}
}

func TestReadStatOddComm(t *testing.T) {
	ppid, comm, ok := readStat(fakeProc(t), 77)
	if !ok || ppid != 1 || comm != "we ird) pro)g" {
		t.Errorf("got ppid=%d comm=%q ok=%v", ppid, comm, ok)
	}
}

func TestFindCgroup2Mount(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mountinfo")
	os.WriteFile(p, []byte(
		"25 1 0:23 / /sys rw,nosuid shared:7 - sysfs sysfs rw\n"+
			"30 25 0:26 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw,nsdelegate\n"), 0o644)
	if got := findCgroup2Mount(p); got != "/sys/fs/cgroup" {
		t.Errorf("got %q", got)
	}
}

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"6.8.0-45-generic", 6, 8, true},
		{"6.1.0-26-amd64", 6, 1, true},
		{"6.12-rc3", 6, 12, true},
		{"5.15.0-91-generic", 5, 15, true},
		{"garbage", 0, 0, false},
	}
	for _, c := range cases {
		maj, min, ok := parseKernelVersion(c.in)
		if maj != c.maj || min != c.min || ok != c.ok {
			t.Errorf("%q: got %d.%d %v", c.in, maj, min, ok)
		}
	}
}

func TestCString(t *testing.T) {
	var b [16]int8
	copyComm(b[:], "a-very-long-process-name")
	if got := cString(b[:]); got != "a-very-long-pro" {
		t.Errorf("got %q (comm keeps 15 chars + NUL)", got)
	}
}
