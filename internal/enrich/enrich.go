// Package enrich maps an IP address to its network owner (ASN), the owner's
// name and its country, using a local file. No lookups ever leave the machine.
//
// File format (CSV, '#' comments allowed), one network per line:
//
//	cidr,asn,country[,owner name]
//	93.184.216.0/24,15133,US,EDGECAST - Edgecast Inc.
//	93.184.217.0/24,15133,US
//
// The owner name is optional and only needs to appear once per ASN (the
// first time it is given wins). Fields may be quoted the CSV way, since names
// contain commas. A file ending in .gz (or starting with the gzip magic bytes)
// is decompressed on the fly. Nested networks are fine: the most specific
// one wins.
//
// The full table (about 700,000 networks, built from the public-domain
// IPtoASN data by cmd/asnbuild, see docs/ASN.md) ships inside a signed
// offline knowledge pack as asn.csv.gz; this package only reads it.
package enrich

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// info is what one network maps to. Values are stored once and shared.
type info struct {
	asn     uint32
	country string // ISO code, upper case, or ""
}

// Disjoint, sorted address ranges. IPv4 is kept apart in 32-bit form
// because it is most of the table and most of the lookups.
type range4 struct {
	start, end uint32
	val        uint32 // index into Table.vals
}

type range6 struct {
	start, end u128
	val        uint32
}

// Table answers lookups in O(log n). Safe for concurrent reads after Load.
type Table struct {
	v4    []range4
	v6    []range6
	vals  []info
	names map[uint32]string
}

// Load reads a table file (plain or gzip-compressed CSV).
func Load(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// Read parses a table from r (plain or gzip-compressed CSV).
func Read(r io.Reader) (*Table, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		br = bufio.NewReaderSize(zr, 1<<16)
	}

	cr := csv.NewReader(br)
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	cr.TrimLeadingSpace = true

	var raws []rawRange
	valIdx := map[info]uint32{}
	t := &Table{names: map[uint32]string{}}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		line, _ := cr.FieldPos(0)
		if err != nil {
			return nil, err
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		if len(rec) != 3 && len(rec) != 4 {
			return nil, fmt.Errorf("line %d: want cidr,asn,country[,name]", line)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(rec[0]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		asn, err := strconv.ParseUint(strings.TrimSpace(rec[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad asn: %v", line, err)
		}
		var v info
		v.asn = uint32(asn)
		if cc := strings.ToUpper(strings.TrimSpace(rec[2])); len(cc) == 2 && cc != "ZZ" && cc != "--" {
			v.country = cc // "ZZ" and "--" mean "unknown" in some sources
		}
		idx, ok := valIdx[v]
		if !ok {
			idx = uint32(len(t.vals))
			valIdx[v] = idx
			t.vals = append(t.vals, v)
		}
		if len(rec) == 4 && v.asn != 0 {
			if _, seen := t.names[v.asn]; !seen {
				if n := strings.TrimSpace(rec[3]); n != "" {
					t.names[v.asn] = n
				}
			}
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 { // ::ffff:a.b.c.d/n is an IPv4 network
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		start, end := prefixBounds(p)
		raws = append(raws, rawRange{start: start, end: end, bits: p.Bits(), v6: !p.Addr().Is4(), val: idx})
	}

	for _, s := range flatten(raws) {
		if s.v6 {
			t.v6 = append(t.v6, range6{s.start, s.end, s.val})
		} else {
			t.v4 = append(t.v4, range4{uint32(s.start.lo), uint32(s.end.lo), s.val})
		}
	}
	return t, nil
}

// Lookup returns the network owner's ASN and country of ip, or (0, "") if
// the table does not cover it.
func (t *Table) Lookup(ip netip.Addr) (uint32, string) {
	v, ok := t.find(ip)
	if !ok {
		return 0, ""
	}
	return v.asn, v.country
}

// Owner returns the name of the network owner with this ASN, such as
// "CLOUDFLARENET - Cloudflare, Inc.", or "" if the table has none.
func (t *Table) Owner(asn uint32) string { return t.names[asn] }

// Len is the number of disjoint address ranges in the table.
func (t *Table) Len() int { return len(t.v4) + len(t.v6) }

func (t *Table) find(ip netip.Addr) (info, bool) {
	if t == nil || !ip.IsValid() {
		return info{}, false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		a := ip.As4()
		x := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].start > x }) - 1
		if i >= 0 && x <= t.v4[i].end {
			return t.vals[t.v4[i].val], true
		}
		return info{}, false
	}
	x := u128From16(ip.As16())
	i := sort.Search(len(t.v6), func(i int) bool { return x.less(t.v6[i].start) }) - 1
	if i >= 0 && !t.v6[i].end.less(x) {
		return t.vals[t.v6[i].val], true
	}
	return info{}, false
}

// --- building the disjoint ranges ---

// u128 is an address as a 128-bit number. IPv4 uses only lo.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }
func (a u128) inc() u128 {
	if a.lo == ^uint64(0) {
		return u128{a.hi + 1, 0}
	}
	return u128{a.hi, a.lo + 1}
}
func (a u128) dec() u128 {
	if a.lo == 0 {
		return u128{a.hi - 1, ^uint64(0)}
	}
	return u128{a.hi, a.lo - 1}
}

func u128From16(b [16]byte) u128 {
	var r u128
	for i := 0; i < 8; i++ {
		r.hi = r.hi<<8 | uint64(b[i])
		r.lo = r.lo<<8 | uint64(b[8+i])
	}
	return r
}

// prefixBounds returns the first and last address of p.
func prefixBounds(p netip.Prefix) (u128, u128) {
	if p.Addr().Is4() {
		a := p.Addr().As4()
		x := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
		size := uint64(1) << (32 - p.Bits())
		return u128{0, x}, u128{0, x + size - 1}
	}
	s := u128From16(p.Addr().As16())
	e := s
	host := 128 - p.Bits()
	switch {
	case host >= 128:
		e = u128{^uint64(0), ^uint64(0)}
	case host >= 64:
		e.lo = ^uint64(0)
		e.hi |= (uint64(1) << (host - 64)) - 1 // nothing when host == 64
	default:
		e.lo |= (uint64(1) << host) - 1
	}
	return s, e
}

type rawRange struct {
	start, end u128
	bits       int
	v6         bool
	val        uint32
}

type segment struct {
	start, end u128
	v6         bool
	val        uint32
}

// flatten turns possibly nested networks into disjoint ranges where the
// most specific network wins, merging neighbours that map to the same value.
// CIDR networks are always either nested or disjoint, never partly
// overlapping, which keeps this simple. If the same network is listed twice,
// the later line wins.
func flatten(raws []rawRange) []segment {
	sort.SliceStable(raws, func(i, j int) bool {
		a, b := raws[i], raws[j]
		if a.v6 != b.v6 {
			return !a.v6
		}
		if a.start != b.start {
			return a.start.less(b.start)
		}
		return a.bits < b.bits // wider first, so the narrower one nests inside
	})
	maxAddr := u128{^uint64(0), ^uint64(0)}
	var out []segment
	emit := func(s, e u128, v6 bool, val uint32) {
		if n := len(out); n > 0 && out[n-1].v6 == v6 && out[n-1].val == val && out[n-1].end != maxAddr && out[n-1].end.inc() == s {
			out[n-1].end = e
			return
		}
		out = append(out, segment{s, e, v6, val})
	}

	var stack []rawRange
	var pos u128  // first address not yet given to a segment
	done := false // pos has run past the last address
	// pop closes the innermost open network.
	pop := func() {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if done || top.end.less(pos) {
			return // fully covered by more specific networks
		}
		emit(pos, top.end, top.v6, top.val)
		if top.end == maxAddr {
			done = true
		} else {
			pos = top.end.inc()
		}
	}
	for i, r := range raws {
		if i > 0 && r.v6 != raws[i-1].v6 {
			for len(stack) > 0 { // IPv4 and IPv6 are separate spaces
				pop()
			}
			done = false
		}
		for len(stack) > 0 && stack[len(stack)-1].end.less(r.start) {
			pop()
		}
		if len(stack) > 0 && !done && pos.less(r.start) {
			top := stack[len(stack)-1]
			emit(pos, r.start.dec(), top.v6, top.val) // the outer network, up to the nested one
		}
		pos, done = r.start, false
		stack = append(stack, r)
	}
	for len(stack) > 0 {
		pop()
	}
	return out
}
