package tamper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/keyseal"
)

type recorder struct{ got []Report }

func (r *recorder) TamperAlert(rep Report) { r.got = append(r.got, rep) }

func newGuard(t *testing.T, dir, machine string) (*Guard, *recorder) {
	t.Helper()
	rec := &recorder{}
	return &Guard{
		Dir:     dir,
		Key:     &keyseal.Sealed{Path: filepath.Join(dir, "db.key"), Sealers: []keyseal.Sealer{&keyseal.MachineID{ID: machine}}},
		DBPath:  filepath.Join(dir, "trafficam.db"),
		Learned: []string{filepath.Join(dir, "model.tcw")},
		Alert:   rec,
		// Pretend files are old so the "new key" grace does not apply.
		Now: func() time.Time { return time.Now().Add(time.Hour) },
	}, rec
}

func mustOpen(t *testing.T, g *Guard) {
	t.Helper()
	st, err := g.Open()
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestCleanStartsAreQuiet(t *testing.T) {
	dir := t.TempDir()
	g, rec := newGuard(t, dir, "A")
	mustOpen(t, g)
	mustOpen(t, g)
	if len(rec.got) != 0 || exists(filepath.Join(dir, AlertFile)) {
		t.Fatalf("false alarm: %+v", rec.got)
	}
}

func TestKeyFromAnotherMachineTrips(t *testing.T) {
	dir := t.TempDir()
	g, _ := newGuard(t, dir, "A")
	mustOpen(t, g)
	os.WriteFile(filepath.Join(dir, "model.tcw"), []byte("learned habits"), 0o600)
	oldKey, _ := os.ReadFile(g.Key.Path)

	g2, rec := newGuard(t, dir, "B") // same files, "other PC"
	st, err := g2.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if len(rec.got) != 1 || !strings.Contains(rec.got[0].What, "cannot be unsealed") {
		t.Fatalf("alerts: %+v", rec.got)
	}
	if exists(filepath.Join(dir, "model.tcw")) {
		t.Fatal("learned model not destroyed")
	}
	if newKey, _ := os.ReadFile(g2.Key.Path); string(newKey) == string(oldKey) {
		t.Fatal("old key file still there")
	}
	text, ok := Pending(dir)
	if !ok || !strings.HasPrefix(text, "TRAFFICAM TAMPER ALERT: ") {
		t.Fatalf("alert file: %q", text)
	}
}

func TestReplacedDatabaseTrips(t *testing.T) {
	dir := t.TempDir()
	g, rec := newGuard(t, dir, "A")
	mustOpen(t, g)
	os.WriteFile(g.DBPath, make([]byte, 8192), 0o600) // not our database
	os.Remove(g.DBPath + "-wal")
	os.Remove(g.DBPath + "-shm")
	mustOpen(t, g)
	if len(rec.got) != 1 || !strings.Contains(rec.got[0].What, "cannot be opened") {
		t.Fatalf("alerts: %+v", rec.got)
	}
}

func TestDeletedFilesTrip(t *testing.T) {
	for _, tc := range []struct{ name, del, want string }{
		{"key", "db.key", "key was deleted"},
		{"db", "trafficam.db", "database was deleted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			g, rec := newGuard(t, dir, "A")
			mustOpen(t, g)
			os.Remove(filepath.Join(dir, tc.del))
			mustOpen(t, g)
			if len(rec.got) != 1 || !strings.Contains(rec.got[0].What, tc.want) {
				t.Fatalf("alerts: %+v", rec.got)
			}
		})
	}
}

func TestPendingAlertRepeatsUntilAck(t *testing.T) {
	dir := t.TempDir()
	g, rec := newGuard(t, dir, "A")
	mustOpen(t, g)
	os.Remove(g.Key.Path)
	mustOpen(t, g) // trips
	mustOpen(t, g) // re-raised
	mustOpen(t, g) // and again
	if len(rec.got) != 3 || !rec.got[1].Pending || !rec.got[2].Pending {
		t.Fatalf("want 1 alert + 2 reminders, got %+v", rec.got)
	}
	if err := Ack(dir); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, g)
	if len(rec.got) != 3 {
		t.Fatal("alert raised after ack")
	}
}

func TestUnavailableIsNotTampering(t *testing.T) {
	dir := t.TempDir()
	g, rec := newGuard(t, dir, "A")
	mustOpen(t, g)
	g.Key.Sealers = []keyseal.Sealer{down{}}
	g.Key.Legacy = nil
	// The file says machine-id, which this provider no longer has: unavailable.
	if _, err := g.Open(); err == nil || errors.Is(err, ErrTampered) {
		t.Fatalf("want a plain error, got %v", err)
	}
	if len(rec.got) != 0 || !exists(g.DBPath) || !exists(g.Key.Path) {
		t.Fatal("something was destroyed although nothing was tampered with")
	}
}

type down struct{}

func (down) Method() string                { return "tpm" }
func (down) Available() error              { return errors.New("busy") }
func (down) Seal([]byte) ([]byte, error)   { return nil, errors.New("busy") }
func (down) Unseal([]byte) ([]byte, error) { return nil, keyseal.ErrUnavailable }

func TestFreshKeyWithoutDatabaseIsNotTampering(t *testing.T) {
	dir := t.TempDir()
	g, rec := newGuard(t, dir, "A")
	g.Now = time.Now // the key below is brand new
	if _, err := g.Key.Key(); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, g) // crash between key and database on first start
	if len(rec.got) != 0 {
		t.Fatalf("false alarm: %+v", rec.got)
	}
}

func TestWatchSeesChangesWhileRunning(t *testing.T) {
	dir := t.TempDir()
	g, _ := newGuard(t, dir, "A")
	st, err := g.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	w, err := g.Watch()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Check(); err != nil {
		t.Fatalf("clean: %v", err)
	}
	b, _ := os.ReadFile(g.Key.Path)
	os.WriteFile(g.Key.Path, append(b, 0), 0o600)
	var d *Detected
	if err := w.Check(); !errors.As(err, &d) || !errors.Is(err, ErrTampered) {
		t.Fatalf("changed key: got %v", err)
	}
	os.WriteFile(g.Key.Path, b, 0o600)
	if err := w.Check(); err != nil {
		t.Fatalf("restored: %v", err)
	}
}

func TestQuarantineKeepsFilesAside(t *testing.T) {
	dir := t.TempDir()
	g, _ := newGuard(t, dir, "A")
	mustOpen(t, g)
	g.Policy = PolicyQuarantine
	r := g.Trip("test", nil)
	if exists(g.DBPath) || exists(g.Key.Path) {
		t.Fatal("files left in place")
	}
	m, _ := filepath.Glob(filepath.Join(dir, "tampered-*", "trafficam.db"))
	if len(m) != 1 || len(r.Destroyed) == 0 {
		t.Fatalf("quarantine: %v %+v", m, r)
	}
}
