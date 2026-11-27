package blocklist

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func TestReloadingPicksUpEdits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch.txt")
	r, err := NewReloading(p) // missing file is fine
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	r.Now = func() time.Time { return now }
	var reported []error
	r.OnError = func(e error) { reported = append(reported, e) }

	m := event.Minute{Host: "evil.example"}
	if r.Current().IsMatch(m) {
		t.Fatal("empty list matched")
	}
	write := func(s string, mt time.Time) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, mt, mt)
	}
	write("evil.example\n", time.Unix(2000, 0))
	if r.Current().IsMatch(m) {
		t.Fatal("re-read before CheckEvery passed")
	}
	now = now.Add(3 * time.Second)
	if !r.Current().IsMatch(m) {
		t.Fatal("edit not picked up")
	}

	// A broken edit keeps the previous good list and is reported once.
	write("evil.example\na b c\n", time.Unix(3000, 0))
	now = now.Add(3 * time.Second)
	if !r.Current().IsMatch(m) {
		t.Fatal("broken edit dropped the good list")
	}
	now = now.Add(3 * time.Second)
	r.Current()
	if len(reported) != 1 {
		t.Fatalf("want 1 error report, got %d", len(reported))
	}

	// Deleting the file empties the list.
	os.Remove(p)
	now = now.Add(3 * time.Second)
	if r.Current().IsMatch(m) {
		t.Fatal("deleted file still matched")
	}
}

func TestNewReloadingRejectsBrokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(p, []byte("a b c\n"), 0o600)
	if _, err := NewReloading(p); err == nil {
		t.Fatal("want error")
	}
}
