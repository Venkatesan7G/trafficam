package enrich

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLongestPrefixWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.csv")
	os.WriteFile(p, []byte("# test\n10.0.0.0/8,100,us\n10.1.0.0/16,200,de\n"), 0o600)
	tb, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if a, c := tb.Lookup(netip.MustParseAddr("10.1.2.3")); a != 200 || c != "DE" {
		t.Fatalf("got %d %s", a, c)
	}
	if a, c := tb.Lookup(netip.MustParseAddr("10.9.9.9")); a != 100 || c != "US" {
		t.Fatalf("got %d %s", a, c)
	}
	if a, c := tb.Lookup(netip.MustParseAddr("10.0.0.0")); a != 100 || c != "US" {
		t.Fatalf("first address of outer network: got %d %s", a, c)
	}
	if a, _ := tb.Lookup(netip.MustParseAddr("8.8.8.8")); a != 0 {
		t.Fatal("unexpected match")
	}
}

func TestNamesQuotesGzipIPv6(t *testing.T) {
	src := `# cidr,asn,country,name
1.0.0.0/24,13335,US,"CLOUDFLARENET - Cloudflare, Inc."
1.1.1.0/24,13335,US
2606:4700::/32,13335,US
2001:db8::/32,64500,zz,Example
::ffff:9.9.9.0/120,19281,CH,QUAD9
`
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(src))
	zw.Close()
	p := filepath.Join(t.TempDir(), "asn.csv.gz")
	os.WriteFile(p, gz.Bytes(), 0o600)
	tb, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"1.1.1.1":          "13335 US",
		"2606:4700::1111":  "13335 US",
		"::ffff:1.0.0.1":   "13335 US", // mapped IPv4 is looked up as IPv4
		"2001:db8:ffff::1": "64500 ",   // ZZ = unknown
		"9.9.9.9":          "19281 CH",
		"2a00::1":          "0 ",
	} {
		a, c := tb.Lookup(netip.MustParseAddr(ip))
		if got := fmt.Sprintf("%d %s", a, c); got != want {
			t.Errorf("%s: got %q, want %q", ip, got, want)
		}
	}
	if n := tb.Owner(13335); n != "CLOUDFLARENET - Cloudflare, Inc." {
		t.Errorf("owner = %q", n)
	}
}

func TestBadLines(t *testing.T) {
	for _, line := range []string{"10.0.0.0/8,100", "10.0.0.0/33,1,US", "10.0.0.0/8,x,US", "10.0.0.0/8,1,US,a,b"} {
		if _, err := Read(strings.NewReader(line + "\n")); err == nil {
			t.Errorf("accepted %q", line)
		}
	}
}

func TestEdgesOfAddressSpace(t *testing.T) {
	tb, err := Read(strings.NewReader("0.0.0.0/0,1,AA\n255.255.255.255/32,2,BB\n::/0,3,CC\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128,4,DD\n"))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]uint32{
		"0.0.0.0": 1, "255.255.255.254": 1, "255.255.255.255": 2,
		"::": 3, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe": 3, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": 4,
	} {
		if a, _ := tb.Lookup(netip.MustParseAddr(ip)); a != want {
			t.Errorf("%s: got %d, want %d", ip, a, want)
		}
	}
}

// Random nested networks, checked against a plain longest-prefix scan.
func TestMatchesNaiveLongestPrefix(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	type net struct {
		p   netip.Prefix
		asn uint32
	}
	var nets []net
	var sb strings.Builder
	for i := 0; i < 3000; i++ {
		var p netip.Prefix
		if i%3 == 0 {
			var b [16]byte
			b[0], b[1], b[2] = 0x20, 0x01, byte(rng.Intn(4))
			b[3] = byte(rng.Intn(256))
			p = netip.PrefixFrom(netip.AddrFrom16(b), 16+rng.Intn(48)).Masked()
		} else {
			b := [4]byte{10, byte(rng.Intn(4)), byte(rng.Intn(256)), byte(rng.Intn(256))}
			p = netip.PrefixFrom(netip.AddrFrom4(b), 8+rng.Intn(25)).Masked()
		}
		asn := uint32(i + 1)
		nets = append(nets, net{p, asn})
		fmt.Fprintf(&sb, "%s,%d,US\n", p, asn)
	}
	tb, err := Read(strings.NewReader(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	naive := func(ip netip.Addr) uint32 {
		best, bits := uint32(0), -1
		for _, n := range nets { // later lines win ties, like Read
			if n.p.Contains(ip) && n.p.Bits() >= bits {
				best, bits = n.asn, n.p.Bits()
			}
		}
		return best
	}
	for i := 0; i < 20000; i++ {
		var ip netip.Addr
		if i%3 == 0 {
			var b [16]byte
			b[0], b[1], b[2], b[3] = 0x20, 0x01, byte(rng.Intn(4)), byte(rng.Intn(256))
			rng.Read(b[4:])
			ip = netip.AddrFrom16(b)
		} else {
			ip = netip.AddrFrom4([4]byte{10, byte(rng.Intn(4)), byte(rng.Intn(256)), byte(rng.Intn(256))})
		}
		if got, want := func() uint32 { a, _ := tb.Lookup(ip); return a }(), naive(ip); got != want {
			t.Fatalf("%s: got AS%d, want AS%d", ip, got, want)
		}
	}
}

func BenchmarkLookup(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 500000; i++ {
		fmt.Fprintf(&sb, "%d.%d.%d.0/24,%d,US\n", 1+i>>16, (i>>8)&255, i&255, i%60000)
	}
	tb, err := Read(strings.NewReader(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	ip := netip.MustParseAddr("3.100.7.9")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.Lookup(ip)
	}
}

// TestRealTable checks a full table built by cmd/asnbuild, if you point
// TRAFFICAM_ASN_TABLE at one:
//
//	TRAFFICAM_ASN_TABLE=asn.csv.gz go test -v -run RealTable ./internal/enrich
func TestRealTable(t *testing.T) {
	path := os.Getenv("TRAFFICAM_ASN_TABLE")
	if path == "" {
		t.Skip("set TRAFFICAM_ASN_TABLE to a built asn.csv.gz")
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	tb, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("%d ranges, %d owners, loaded in %v, ~%d MB kept in memory",
		tb.Len(), len(tb.names), took.Round(time.Millisecond), (after.HeapAlloc-before.HeapAlloc)>>20)
	for ip, want := range map[string]uint32{"1.1.1.1": 13335, "8.8.8.8": 15169, "2606:4700:4700::1111": 13335, "9.9.9.9": 19281} {
		asn, cc := tb.Lookup(netip.MustParseAddr(ip))
		t.Logf("%s -> AS%d %s %q", ip, asn, cc, tb.Owner(asn))
		if asn != want {
			t.Errorf("%s: AS%d, want AS%d", ip, asn, want)
		}
	}
	runtime.KeepAlive(tb)
}
