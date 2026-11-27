// Package enrich maps an IP address to its network owner (ASN) and country
// using a local file. No lookups ever leave the machine.
//
// File format (CSV, '#' comments allowed), one network per line:
//
//	cidr,asn,country
//	93.184.216.0/24,15133,US
//
// The file is meant to ship inside a signed offline "knowledge pack"; how it
// is built (e.g. from a public RIR/BGP snapshot) is outside the core.
package enrich

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

type entry struct {
	prefix  netip.Prefix
	asn     uint32
	country string
}

// Table answers longest-prefix lookups. Safe for concurrent reads after Load.
type Table struct{ entries []entry } // sorted by prefix length, longest first

// Load reads the CSV file.
func Load(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := &Table{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s:%d: want cidr,asn,country", path, n)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, n, err)
		}
		asn, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad asn: %v", path, n, err)
		}
		t.entries = append(t.entries, entry{p.Masked(), uint32(asn), strings.ToUpper(strings.TrimSpace(parts[2]))})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(t.entries, func(i, j int) bool { return t.entries[i].prefix.Bits() > t.entries[j].prefix.Bits() })
	return t, nil
}

// Lookup returns the most specific match, or (0, "") if none.
// (A linear scan is fine for the small tables the core targets; swap for a
// trie if packs grow large.)
func (t *Table) Lookup(ip netip.Addr) (uint32, string) {
	ip = ip.Unmap()
	for _, e := range t.entries {
		if e.prefix.Contains(ip) {
			return e.asn, e.country
		}
	}
	return 0, ""
}
