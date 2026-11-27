// Package trustos is the list of core operating-system programs whose new
// destinations are not alerted ("trust core OS services").
//
// Trusting a program only switches off the two novelty rules for it (new
// program, new destination). It does NOT switch off the known-bad list, your
// watch list, or the model, which still judges the program against its own
// habits. So a hijacked system service that suddenly behaves differently can
// still be caught; it just will not alert merely for visiting a new server.
//
// Every entry names an exact executable path (with * allowed for version
// folders), optionally narrowed by signer and OS service. Signer alone is
// never enough: "Microsoft Windows" also signs powershell.exe, certutil.exe
// and bitsadmin.exe, which malware borrows to download things.
//
// The built-in list (default.json) is small and conservative. A signed
// knowledge pack can replace it (kind "trusted-os").
package trustos

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

//go:embed default.json
var defaultJSON []byte

// Entry is one trusted program.
type Entry struct {
	OS      string `json:"os"`                // "windows", "linux" (runtime.GOOS)
	Path    string `json:"path"`              // executable path, * matches within one folder level
	Signer  string `json:"signer,omitempty"`  // must also match, if given
	Service string `json:"service,omitempty"` // must also match, if given (svchost service / systemd unit)
	Note    string `json:"note,omitempty"`    // why it is trusted
}

type file struct {
	Format   int     `json:"format"`
	Programs []Entry `json:"programs"`
}

// List is immutable after loading; nil is an empty list.
type List struct{ entries []Entry }

// Default is the built-in list.
func Default() *List {
	l, err := Parse(defaultJSON)
	if err != nil {
		panic(err) // the embedded file is tested
	}
	return l
}

// Load reads a list file (from a knowledge pack).
func Load(p string) (*List, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	l, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return l, nil
}

// Parse reads the JSON format.
func Parse(b []byte) (*List, error) {
	var f file
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("trusted OS list: %w", err)
	}
	if f.Format != 1 {
		return nil, fmt.Errorf("trusted OS list: format %d not supported", f.Format)
	}
	for i, e := range f.Programs {
		if e.OS == "" || e.Path == "" {
			return nil, fmt.Errorf("trusted OS list: entry %d needs os and path", i)
		}
		if strings.Contains(e.Path, "**") {
			return nil, fmt.Errorf("trusted OS list: entry %d: ** is not allowed", i)
		}
		if _, err := path.Match(norm(e.OS, e.Path), ""); err != nil {
			return nil, fmt.Errorf("trusted OS list: entry %d: %v", i, err)
		}
	}
	return &List{entries: f.Programs}, nil
}

// Len is the number of entries for any OS.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// Trusted reports whether p is a trusted OS program on this OS.
func (l *List) Trusted(p event.Program) bool { return l.match(runtime.GOOS, p) }

func (l *List) match(goos string, p event.Program) bool {
	if l == nil || p.Path == "" {
		return false
	}
	for _, e := range l.entries {
		if e.OS != goos {
			continue
		}
		if ok, _ := path.Match(norm(goos, e.Path), norm(goos, p.Path)); !ok {
			continue
		}
		if e.Signer != "" && !strings.EqualFold(e.Signer, p.Signer) {
			continue
		}
		if e.Service != "" && !strings.EqualFold(e.Service, p.Service) {
			continue
		}
		return true
	}
	return false
}

// norm makes Windows paths comparable: case-insensitive, forward slashes.
func norm(goos, p string) string {
	if goos == "windows" {
		return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	}
	return p
}
