// Command asnbuild turns the public IPtoASN database into trafficam's
// offline ASN/country table (asn.csv.gz), the file internal/enrich reads.
//
// It runs on the machine that builds a knowledge pack, never on users' PCs,
// and it never downloads anything itself: you fetch the input by hand.
//
//	curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
//	go run ./cmd/asnbuild -in ip2asn-combined.tsv.gz -out asn.csv.gz
//
// Input: IPtoASN's tab-separated "range_start range_end AS_number
// country_code AS_description" lines (plain or .gz). Ranges marked
// "Not routed" (AS 0) are dropped. Each range is split into CIDR networks.
//
// The IPtoASN data is public domain (Open Data Commons PDDL 1.0), so it can
// ship inside trafficam's GPL-3.0 packs without conditions. See docs/ASN.md.
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	in := flag.String("in", "ip2asn-combined.tsv.gz", "IPtoASN TSV file (plain or .gz)")
	out := flag.String("out", "asn.csv.gz", "output table (.gz to compress)")
	flag.Parse()
	st, err := build(*in, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "asnbuild:", err)
		os.Exit(1)
	}
	fmt.Printf("asnbuild: %d ranges in, %d networks out, %d owners, %d skipped (not routed)\n",
		st.ranges, st.networks, st.owners, st.skipped)
}

type stats struct{ ranges, networks, owners, skipped int }

func build(inPath, outPath string) (stats, error) {
	f, err := os.Open(inPath)
	if err != nil {
		return stats{}, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(inPath, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return stats{}, err
		}
		defer zr.Close()
		r = zr
	}

	tmp := outPath + ".tmp"
	of, err := os.Create(tmp)
	if err != nil {
		return stats{}, err
	}
	defer os.Remove(tmp) // no-op after the rename
	var w io.Writer = of
	var zw *gzip.Writer
	if strings.HasSuffix(outPath, ".gz") {
		zw, _ = gzip.NewWriterLevel(of, gzip.BestCompression)
		zw.ModTime = time.Time{} // same input -> byte-identical output
		w = zw
	}
	bw := bufio.NewWriterSize(w, 1<<16)

	st, err := convert(r, bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil && zw != nil {
		err = zw.Close()
	}
	if cerr := of.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return st, err
	}
	return st, os.Rename(tmp, outPath)
}

// convert reads IPtoASN TSV from r and writes the table CSV to w.
func convert(r io.Reader, w *bufio.Writer) (stats, error) {
	var st stats
	named := map[uint32]bool{}
	fmt.Fprintln(w, "# trafficam ASN/country table: cidr,asn,country[,owner]")
	fmt.Fprintln(w, "# Built from IPtoASN (https://iptoasn.com), public domain (ODC PDDL 1.0).")
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if text == "" {
			continue
		}
		cols := strings.SplitN(text, "\t", 5)
		if len(cols) < 4 {
			return st, fmt.Errorf("line %d: want 5 tab-separated columns", line)
		}
		st.ranges++
		start, err1 := netip.ParseAddr(cols[0])
		end, err2 := netip.ParseAddr(cols[1])
		asn, err3 := strconv.ParseUint(cols[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil {
			return st, fmt.Errorf("line %d: bad range or AS number: %q", line, text)
		}
		if asn == 0 {
			st.skipped++ // "Not routed"
			continue
		}
		cc := strings.ToUpper(strings.TrimSpace(cols[3]))
		if len(cc) != 2 || cc == "ZZ" || cc == "NONE" {
			cc = ""
		}
		name := ""
		if len(cols) == 5 && !named[uint32(asn)] {
			name = strings.TrimSpace(cols[4])
			if name == "Not routed" {
				name = ""
			}
			if name != "" {
				named[uint32(asn)] = true
				st.owners++
			}
		}
		prefixes, err := rangeToPrefixes(start.Unmap(), end.Unmap())
		if err != nil {
			return st, fmt.Errorf("line %d: %v", line, err)
		}
		for _, p := range prefixes {
			st.networks++
			w.WriteString(p.String())
			w.WriteByte(',')
			w.WriteString(strconv.FormatUint(asn, 10))
			w.WriteByte(',')
			w.WriteString(cc)
			if name != "" {
				w.WriteByte(',')
				w.WriteString(csvQuote(name))
				name = "" // once per AS is enough
			}
			w.WriteByte('\n')
		}
	}
	return st, sc.Err()
}

// csvQuote quotes a field if it contains a comma, quote or newline.
func csvQuote(s string) string {
	s = strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
	if !strings.ContainsAny(s, `,"`) {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// rangeToPrefixes splits the inclusive range [a, b] into the fewest CIDR
// networks that cover exactly it.
func rangeToPrefixes(a, b netip.Addr) ([]netip.Prefix, error) {
	if a.Is4() != b.Is4() || b.Less(a) {
		return nil, fmt.Errorf("bad range %s - %s", a, b)
	}
	var out []netip.Prefix
	bitsTotal := a.BitLen()
	for {
		// Grow the network at a for as long as it starts at a and stays
		// inside the range.
		bits := bitsTotal
		for bits > 0 {
			p := netip.PrefixFrom(a, bits-1).Masked()
			if p.Addr() != a || lastAddr(p).Compare(b) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(a, bits)
		out = append(out, p)
		last := lastAddr(p)
		if last.Compare(b) >= 0 {
			return out, nil
		}
		a = last.Next()
	}
}

// lastAddr returns the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
