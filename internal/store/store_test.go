package store

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
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

// A database written by the first release (schema v1) must upgrade in place.
func TestUpgradeFromV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	k := key(3)
	raw, err := sql.Open("sqlite3", "file:"+path+"?_pragma_key="+url.QueryEscape("x'"+hex.EncodeToString(k)+"'")+"&_pragma_cipher_page_size=4096")
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
INSERT INTO meta VALUES('db_schema','1');
CREATE TABLE minutes (id INTEGER PRIMARY KEY, start INTEGER NOT NULL, prog_key TEXT NOT NULL, prog_name TEXT NOT NULL,
 proto TEXT NOT NULL, dir TEXT NOT NULL, host TEXT NOT NULL, remote_ip TEXT NOT NULL, port INTEGER NOT NULL, flows INTEGER NOT NULL,
 packets INTEGER NOT NULL, bytes_in INTEGER NOT NULL, bytes_out INTEGER NOT NULL, failed INTEGER NOT NULL, score REAL,
 alerted INTEGER NOT NULL DEFAULT 0, schema_v INTEGER NOT NULL);
INSERT INTO minutes(start,prog_key,prog_name,proto,dir,host,remote_ip,port,flows,packets,bytes_in,bytes_out,failed,schema_v)
 VALUES(1000,'/bin/p','p','tcp','out','old.example','',443,1,1,1,1,0,1);`)
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path, k)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	defer s.Close()
	rows, err := s.Since(time.Unix(0, 0))
	if err != nil || len(rows) != 1 || rows[0].Minute.Host != "old.example" {
		t.Fatalf("old row lost: %v %+v", err, rows)
	}
	if at, err := s.InstalledAt(); err != nil || time.Since(at) > time.Minute {
		t.Fatalf("installed_at: %v %v", at, err)
	}
}

func TestNewFieldsAndSeenCounters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "n.db"), key(4))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	day := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	m := event.Minute{V: event.SchemaVersion, Start: day, Program: event.Program{Name: "p", Path: "/bin/p", Parent: "bash", Signer: "ACME"},
		Proto: event.TCP, Dir: event.Outbound, Host: "h.example", Port: 443, ASN: 64500, Country: "NL", DurationMs: 1234}
	if err := s.Insert([]Scored{{Minute: m}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Since(day)
	g := got[0].Minute
	if g.Program.Parent != "bash" || g.Program.Signer != "ACME" || g.ASN != 64500 || g.Country != "NL" || g.DurationMs != 1234 {
		t.Fatalf("new fields not stored: %+v", g)
	}
	// Two minutes on day 1, one on day 2 => days=2, minutes=3.
	m2, m3 := m, m
	m2.Start = day.Add(time.Minute)
	m3.Start = day.Add(24 * time.Hour)
	if err := s.SeenUpdate([]event.Minute{m, m2, m3}); err != nil {
		t.Fatal(err)
	}
	seen, _ := s.SeenGet([]SeenKey{KeyOf(m), {Prog: "x", Host: "y"}})
	v := seen[KeyOf(m)]
	if len(seen) != 1 || v.Days != 2 || v.Minutes != 3 || !v.First.Equal(day) {
		t.Fatalf("seen=%+v", seen)
	}
	if first, hosts, err := s.ProgramSummary("/bin/p"); err != nil || hosts != 1 || !first.Equal(day) {
		t.Fatalf("summary %v %d %v", first, hosts, err)
	}
	if first, hosts, _ := s.ProgramSummary("/bin/none"); !first.IsZero() || hosts != 0 {
		t.Fatal("unknown program should be empty")
	}
}
