package tamper

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/keyseal"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Detected is a tamper finding that has not been handled yet. Trip it once
// the store is closed (Windows cannot delete open files).
type Detected struct {
	What string
	Err  error
}

func (d *Detected) Error() string {
	if d.Err == nil {
		return fmt.Sprintf("%v: %s", ErrTampered, d.What)
	}
	return fmt.Sprintf("%v: %s: %v", ErrTampered, d.What, d.Err)
}
func (d *Detected) Unwrap() error { return ErrTampered }

// newKeyGrace: a key file younger than this with no database next to it is
// a first start that crashed between the two writes, not tampering.
const newKeyGrace = 5 * time.Minute

// Check looks for tampering at start-up without changing anything. It
// returns nil, or a *Detected. Errors that are not evidence of tampering
// (TPM busy, disk errors, database locked) come back as plain errors.
func (g *Guard) Check() (key []byte, err error) {
	keyInfo, kerr := os.Stat(g.Key.Path)
	_, derr := os.Stat(g.DBPath)
	keyExists, dbExists := kerr == nil, derr == nil
	if !keyExists && dbExists {
		return nil, &Detected{What: "the database key was deleted"}
	}
	if keyExists && !dbExists && g.now().Sub(keyInfo.ModTime()) > newKeyGrace {
		return nil, &Detected{What: "the database was deleted"}
	}
	if !keyExists {
		return nil, nil // first start
	}
	key, err = g.Key.Key()
	if errors.Is(err, keyseal.ErrSealMismatch) {
		return nil, &Detected{What: "the database key cannot be unsealed on this PC", Err: err}
	}
	if err != nil {
		return nil, fmt.Errorf("could not unlock the database key (this is not treated as tampering; nothing was changed): %w", err)
	}
	return key, nil
}

// Open opens the store with the tamper response in place: an unacknowledged
// alert is raised again, tampering found at start-up is tripped (destroy,
// report, alert), and a fresh key and database are made.
func (g *Guard) Open() (*store.Store, error) {
	g.RaisePending()
	st, err := g.open()
	var d *Detected
	if errors.As(err, &d) {
		g.Trip(d.What, d.Err)
		st, err = g.open()
		if errors.As(err, &d) { // cannot happen on a working disk; never loop
			return nil, fmt.Errorf("tampering detected again right after a fresh start: %w", err)
		}
	}
	return st, err
}

func (g *Guard) open() (*store.Store, error) {
	key, err := g.Check()
	if err != nil {
		return nil, err
	}
	if key == nil {
		if key, err = g.Key.Key(); err != nil {
			return nil, err
		}
	}
	st, err := store.Open(g.DBPath, key)
	if store.IsWrongKey(err) {
		return nil, &Detected{What: "the database cannot be opened with its key (replaced or modified)", Err: err}
	}
	return st, err
}

// Watch remembers what the key and database files looked like after a
// successful open, so changes while trafficam runs can be spotted.
type Watch struct {
	g       *Guard
	keyHash [32]byte
	db      os.FileInfo
}

// Watch takes the snapshot. Call it right after Open.
func (g *Guard) Watch() (*Watch, error) {
	b, err := os.ReadFile(g.Key.Path)
	if err != nil {
		return nil, err
	}
	db, err := os.Stat(g.DBPath)
	if err != nil {
		return nil, err
	}
	return &Watch{g: g, keyHash: sha256.Sum256(b), db: db}, nil
}

// Check returns a *Detected if the key file changed or disappeared, or the
// database file was deleted or swapped for another file. Read errors other
// than "not found" are not treated as tampering.
func (w *Watch) Check() error {
	b, err := os.ReadFile(w.g.Key.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &Detected{What: "the database key was deleted while trafficam was running"}
	case err != nil:
		return nil
	}
	if h := sha256.Sum256(b); !bytes.Equal(h[:], w.keyHash[:]) {
		return &Detected{What: "the database key file was changed while trafficam was running"}
	}
	db, err := os.Stat(w.g.DBPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &Detected{What: "the database was deleted while trafficam was running"}
	case err != nil:
		return nil
	}
	if !os.SameFile(db, w.db) {
		return &Detected{What: "the database file was replaced while trafficam was running"}
	}
	return nil
}
