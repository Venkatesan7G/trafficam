package main

import (
	"bufio"
	"bytes"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Venkatesan7G/trafficam/internal/enrich"
)

func TestRangeToPrefixes(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"1.0.0.0", "1.0.0.255", "1.0.0.0/24"},
		{"1.0.4.0", "1.0.7.255", "1.0.4.0/22"},
		{"10.0.0.1", "10.0.0.6", "10.0.0.1/32 10.0.0.2/31 10.0.0.4/31 10.0.0.6/32"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"255.255.255.255", "255.255.255.255", "255.255.255.255/32"},
		{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::/32"},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/0"},
	} {
		ps, err := rangeToPrefixes(netip.MustParseAddr(tc.a), netip.MustParseAddr(tc.b))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range ps {
			got = append(got, p.String())
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%s-%s: got %v, want %s", tc.a, tc.b, got, tc.want)
		}
	}
	if _, err := rangeToPrefixes(netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Error("accepted a backwards range")
	}
}

// The builder's output must load in internal/enrich and answer like the input.
func TestConvertRoundTrip(t *testing.T) {
	in := "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
		"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
		"1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP - Gtelecom \"Pty\" Ltd\n" +
		"1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
		"2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	st, err := convert(strings.NewReader(in), w)
	if err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if st.ranges != 5 || st.skipped != 1 || st.owners != 2 {
		t.Errorf("stats %+v", st)
	}
	tb, err := enrich.Read(&out)
	if err != nil {
		t.Fatalf("output does not load: %v\n%s", err, out.String())
	}
	for ip, want := range map[string]uint32{"1.0.0.9": 13335, "1.0.2.1": 0, "1.0.5.5": 38803, "1.1.1.1": 13335, "2606:4700::1": 13335} {
		if a, _ := tb.Lookup(netip.MustParseAddr(ip)); a != want {
			t.Errorf("%s: AS%d, want AS%d", ip, a, want)
		}
	}
	if n := tb.Owner(38803); n != `GTELECOM-AS-AP - Gtelecom "Pty" Ltd` {
		t.Errorf("owner %q", n)
	}
}

func TestBuildIsReproducible(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.tsv")
	writeFile(t, in, "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")
	var outs [2][]byte
	for i := range outs {
		o := filepath.Join(dir, "asn.csv.gz")
		if _, err := build(in, o); err != nil {
			t.Fatal(err)
		}
		outs[i] = readFile(t, o)
	}
	if !bytes.Equal(outs[0], outs[1]) {
		t.Fatal("same input gave different output")
	}
}
