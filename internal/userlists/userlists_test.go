package userlists

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Venkatesan7G/trafficam/internal/blocklist"
	"github.com/Venkatesan7G/trafficam/internal/event"
)

func TestAddRemoveKeepsComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "ignore.txt")
	f := File{Path: p, Kind: Ignore}

	if changed, err := f.Add("*.Updates.Example.com", "", "my updater"); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if changed, _ := f.Add("updates.example.com", "", ""); changed {
		t.Fatal("duplicate was added")
	}
	if _, err := f.Add("198.51.100.0/24", "curl", ""); err != nil {
		t.Fatal(err)
	}
	// A hand-written comment and rule survive edits.
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte("# my own note\nkeep.example\n")...), 0o600)

	es, err := f.Entries()
	if err != nil || len(es) != 3 {
		t.Fatalf("entries %v %v", es, err)
	}
	if es[0].Pattern != "Updates.Example.com" || es[0].Note != "my updater" || es[1].Program != "curl" {
		t.Fatalf("got %+v", es)
	}
	if n, err := f.Remove("updates.example.com", ""); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if n, _ := f.Remove("198.51.100.0/24", "firefox"); n != 0 {
		t.Fatal("removed a rule for another program")
	}
	b, _ = os.ReadFile(p)
	s := string(b)
	if !strings.Contains(s, "# my own note") || !strings.Contains(s, "keep.example") || !strings.Contains(s, "# trafficam ignore list") {
		t.Fatalf("lost content:\n%s", s)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("mode %v", st.Mode())
	}
	// The result is still a valid blocklist file.
	l, err := blocklist.Load(p)
	if err != nil || !l.IsMatch(event.Minute{Host: "198.51.100.5", Program: event.Program{Name: "curl"}}) {
		t.Fatal("file does not load or match", err)
	}
}

func TestValidate(t *testing.T) {
	bad := []string{"", "a b", "ex*ample.com", "foo/bar", "x#y"}
	for _, s := range bad {
		if _, err := Validate(s, ""); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{"example.com", "*.example.com", "10.0.0.1", "2001:db8::/32", "10.0.0.0/8"} {
		if _, err := Validate(s, ""); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	if _, err := Validate("example.com", "two words"); err == nil {
		t.Error("program with a space accepted")
	}
}

func TestEnsureWritesHeaderOnce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch.txt")
	f := File{Path: p, Kind: Watch}
	if err := f.Ensure(); err != nil {
		t.Fatal(err)
	}
	f.Add("example.com", "", "")
	if err := f.Ensure(); err != nil {
		t.Fatal(err)
	}
	if es, _ := f.Entries(); len(es) != 1 {
		t.Fatal("Ensure overwrote the file")
	}
}

func TestWholeProgram(t *testing.T) {
	f := File{Path: filepath.Join(t.TempDir(), "ignore.txt"), Kind: Ignore}
	if _, err := f.Add("*", "", ""); err == nil {
		t.Fatal("* without a program accepted")
	}
	if changed, err := f.Add("*", "backupd", "my backup tool"); err != nil || !changed {
		t.Fatal(changed, err)
	}
	l, err := blocklist.Load(f.Path)
	if err != nil || !l.IsMatch(event.Minute{Host: "z.example", Program: event.Program{Name: "backupd"}}) {
		t.Fatal("whole-program rule does not match", err)
	}
	if n, _ := f.Remove("*", "backupd"); n != 1 {
		t.Fatal("not removed")
	}
}
