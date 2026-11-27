// Package userlists lets people edit their own watch and ignore lists
// without opening a text editor or learning the file format.
//
// The lists are the plain-text files read by package blocklist (one rule per
// line: "pattern [program]"). This package adds, removes and shows rules
// while keeping the user's own comments and blank lines exactly as they were.
// Every change is checked before it is written, and written atomically
// (temporary file, then rename), so a half-written or invalid file can never
// reach the running watcher. The watcher picks up the change by itself
// within a few seconds (blocklist.Reloading).
package userlists

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/Venkatesan7G/trafficam/internal/blocklist"
)

// Kind names one of the user's lists.
type Kind string

const (
	Watch  Kind = "watch"  // "alert me anyway"
	Ignore Kind = "ignore" // "don't tell me about this"
)

// ParseKind accepts "watch" or "ignore".
func ParseKind(s string) (Kind, error) {
	switch k := Kind(strings.ToLower(s)); k {
	case Watch, Ignore:
		return k, nil
	}
	return "", fmt.Errorf("unknown list %q (want watch or ignore)", s)
}

// FileName is the default file name of a list inside the data folder.
func (k Kind) FileName() string { return string(k) + ".txt" }

// Path is the default location of a list inside the data folder.
func Path(dataDir string, k Kind) string { return filepath.Join(dataDir, k.FileName()) }

// Header is written at the top of a new list so that anyone who opens the
// file by hand knows what it does and how to write a rule.
func Header(k Kind) string {
	what := "Destinations on this list ALWAYS raise an alert, even if trafficam has\n# learned that they are normal."
	if k == Ignore {
		what = "Destinations on this list never raise a \"new\" or \"unusual\" alert.\n# They do NOT silence the known-bad list or your watch list."
	}
	return fmt.Sprintf(`# trafficam %s list
#
# %s
#
# One rule per line. Anything after # is a comment. Examples:
#   example.com              this domain and every subdomain (www.example.com, ...)
#   203.0.113.7              one IP address
#   198.51.100.0/24          a whole network
#   updates.example.net curl only when the program "curl" connects there
#                            (program name, or its full path)
#
# Changes are picked up automatically within a few seconds.

`, k, what)
}

// Entry is one rule in a list.
type Entry struct {
	Pattern string `json:"pattern"`
	Program string `json:"program,omitempty"`
	Note    string `json:"note,omitempty"` // the comment after the rule, if any
	Line    int    `json:"line"`           // 1-based line number in the file
}

// String is the rule as it would appear in the file (without the note).
func (e Entry) String() string {
	if e.Program != "" {
		return e.Pattern + " " + e.Program
	}
	return e.Pattern
}

// File is one list file on disk.
type File struct {
	Path string
	Kind Kind
}

// Entries returns the rules in file order. A missing file has no rules.
func (f File) Entries() ([]Entry, error) {
	lines, err := f.read()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for i, l := range lines {
		if e, ok := parse(l); ok {
			e.Line = i + 1
			out = append(out, e)
		}
	}
	return out, nil
}

// Validate checks one rule without changing anything. It returns the rule in
// its normalised form ("pattern" or "pattern program").
func Validate(pattern, program string) (Entry, error) {
	pattern, program = strings.TrimSpace(pattern), strings.TrimSpace(program)
	if pattern == "" {
		return Entry{}, errors.New("the rule is empty")
	}
	if strings.ContainsAny(pattern+program, "#\r\n\t ") {
		return Entry{}, errors.New("a pattern or program name cannot contain spaces, tabs, line breaks or #")
	}
	if strings.HasPrefix(pattern, "*.") {
		// People often type wildcards; a plain domain already covers subdomains.
		pattern = pattern[2:]
	}
	if !validPattern(pattern) {
		return Entry{}, fmt.Errorf("%q is not a domain, IP address or network (example.com, 203.0.113.7, 198.51.100.0/24)", pattern)
	}
	e := Entry{Pattern: pattern, Program: program}
	if err := blocklist.New().Add(e.String()); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func validPattern(p string) bool {
	if _, err := netip.ParsePrefix(p); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(p); err == nil {
		return true
	}
	// A domain name: letters, digits, '-', '_' and dots, no empty labels.
	if len(p) > 253 || strings.Contains(strings.TrimSuffix(p, "."), "..") || strings.HasPrefix(p, ".") {
		return false
	}
	return strings.IndexFunc(p, func(r rune) bool {
		return !(r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) < 0
}

// Add appends a rule (with an optional note) unless the same rule is already
// there. It reports whether the file changed.
func (f File) Add(pattern, program, note string) (bool, error) {
	e, err := Validate(pattern, program)
	if err != nil {
		return false, err
	}
	note = strings.Join(strings.Fields(note), " ") // one line, no tabs
	lines, err := f.read()
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if old, ok := parse(l); ok && same(old, e) {
			return false, nil
		}
	}
	if lines == nil {
		lines = strings.Split(strings.TrimRight(Header(f.Kind), "\n"), "\n")
		lines = append(lines, "")
	}
	line := e.String()
	if note != "" {
		line += "    # " + note
	}
	return true, f.write(append(lines, line))
}

// Remove deletes every line holding this rule (pattern and program must both
// match; case does not matter). Comments and other rules are kept. It
// reports how many lines were removed.
func (f File) Remove(pattern, program string) (int, error) {
	want := Entry{Pattern: strings.TrimSpace(pattern), Program: strings.TrimSpace(program)}
	if strings.HasPrefix(want.Pattern, "*.") {
		want.Pattern = want.Pattern[2:]
	}
	lines, err := f.read()
	if err != nil || lines == nil {
		return 0, err
	}
	kept := lines[:0:0]
	n := 0
	for _, l := range lines {
		if e, ok := parse(l); ok && same(e, want) {
			n++
			continue
		}
		kept = append(kept, l)
	}
	if n == 0 {
		return 0, nil
	}
	return n, f.write(kept)
}

// Ensure creates the file with its explanatory header if it does not exist,
// so that "open in editor" always opens something helpful.
func (f File) Ensure() error {
	if _, err := os.Stat(f.Path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return f.write(strings.Split(strings.TrimRight(Header(f.Kind), "\n"), "\n"))
}

func same(a, b Entry) bool {
	return strings.EqualFold(strings.TrimSuffix(a.Pattern, "."), strings.TrimSuffix(b.Pattern, ".")) &&
		strings.EqualFold(a.Program, b.Program)
}

func parse(line string) (Entry, bool) {
	var note string
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line, note = line[:i], strings.TrimSpace(line[i+1:])
	}
	fs := strings.Fields(line)
	switch len(fs) {
	case 1:
		return Entry{Pattern: fs[0], Note: note}, true
	case 2:
		return Entry{Pattern: fs[0], Program: fs[1], Note: note}, true
	}
	return Entry{}, false
}

// read returns the file's lines, or nil if it does not exist.
func (f File) read() ([]string, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	return lines, sc.Err()
}

// write checks that the whole new file parses, then replaces the old one
// atomically. The file is private to its owner (the data folder is too).
func (f File) write(lines []string) error {
	body := strings.Join(lines, "\n") + "\n"
	check := blocklist.New()
	for i, l := range lines {
		if err := check.Add(l); err != nil {
			return fmt.Errorf("%s:%d: %v (nothing was changed)", f.Path, i+1, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), "."+filepath.Base(f.Path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}
