// Package blocklist matches destinations against plain-text lists. It backs
// three user-visible features, all offline and all opt-in:
//
//   - the known-bad snapshot (e.g. an abuse.ch export) -> always alert
//   - the user's "alert me anyway" list
//   - the user's "ignore" list
//
// File format, one rule per line, '#' starts a comment:
//
//	evil.example.com            domain: also matches sub.evil.example.com
//	203.0.113.7                 single IP
//	198.51.100.0/24             network
//	cdn.example.net firefox     rule that applies only to the program "firefox"
//	                            (matches program name or full path)
//
// Matching is case-insensitive for names.
package blocklist

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

type rule struct {
	text   string // original pattern, for messages
	prefix netip.Prefix
	prog   string // optional program filter (lower-case)
}

// List is immutable after Load, so it is safe for concurrent use.
type List struct {
	domains map[string][]rule // lower-case domain -> rules
	nets    []rule
	size    int
}

// New returns an empty list.
func New() *List { return &List{domains: map[string][]rule{}} }

// Load reads a list from a file.
func Load(path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l := New()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if err := l.Add(sc.Text()); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, n, err)
		}
	}
	return l, sc.Err()
}

// Len is the number of rules (nil-safe).
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return l.size
}

// Add parses one line (blank lines and comments are ignored).
func (l *List) Add(line string) error {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	if len(fields) > 2 {
		return fmt.Errorf("want 'pattern [program]', got %q", line)
	}
	r := rule{text: fields[0]}
	if len(fields) == 2 {
		r.prog = strings.ToLower(fields[1])
	}
	if p, err := netip.ParsePrefix(fields[0]); err == nil {
		r.prefix = p.Masked()
		l.nets = append(l.nets, r)
	} else if a, err := netip.ParseAddr(fields[0]); err == nil {
		a = a.Unmap()
		r.prefix = netip.PrefixFrom(a, a.BitLen())
		l.nets = append(l.nets, r)
	} else {
		d := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		l.domains[d] = append(l.domains[d], r)
	}
	l.size++
	return nil
}

// Match reports the first rule that matches this row, if any (nil-safe).
func (l *List) Match(m event.Minute) (string, bool) {
	if l == nil || l.size == 0 {
		return "", false
	}
	if m.Host != "" {
		// Walk "a.b.evil.com" -> "b.evil.com" -> "evil.com" -> "com".
		for h := strings.ToLower(strings.TrimSuffix(m.Host, ".")); h != ""; {
			for _, r := range l.domains[h] {
				if progOK(r, m.Program) {
					return r.text, true
				}
			}
			i := strings.IndexByte(h, '.')
			if i < 0 {
				break
			}
			h = h[i+1:]
		}
	}
	// The host may itself be an IP; the row also keeps the last remote IP.
	for _, s := range []string{m.Host, m.RemoteIP} {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap()
		for _, r := range l.nets {
			if r.prefix.Contains(a) && progOK(r, m.Program) {
				return r.text, true
			}
		}
	}
	return "", false
}

func progOK(r rule, p event.Program) bool {
	return r.prog == "" || r.prog == strings.ToLower(p.Name) || r.prog == strings.ToLower(p.Path)
}

// IsMatch is Match without the rule text (nil-safe).
func (l *List) IsMatch(m event.Minute) bool { _, ok := l.Match(m); return ok }
