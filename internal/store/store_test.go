package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestRoundTripAndEncryptedOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := Open(path, key(1))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	sc := 0.9
	err = s.Insert([]Scored{{Minute: event.Minute{V: 1, Start: start, Program: event.Program{Name: "p", Path: "/bin/p"},
		Proto: event.TCP, Dir: event.Outbound, Host: "secret-host.example", Port: 443, Flows: 3}, Score: &sc, Alerted: true}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Since(start)
	if err != nil || len(got) != 1 {
		t.Fatalf("since: %v n=%d", err, len(got))
	}
	m := got[0].Minute
	if m.Host != "secret-host.example" || m.Program.Path != "/bin/p" || got[0].Score == nil || !got[0].Alerted || !m.Start.Equal(start) {
		t.Fatalf("bad row: %+v", got[0])
	}
	s.Close()

	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("secret-host")) || bytes.HasPrefix(raw, []byte("SQLite format 3")) {
		t.Fatal("database is not encrypted on disk")
	}
	// Wrong key must be refused.
	if _, err := Open(path, key(2)); !errors.Is(err, ErrCannotOpen) {
		t.Fatalf("want ErrCannotOpen, got %v", err)
	}
}
