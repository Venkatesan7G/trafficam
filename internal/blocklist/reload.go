package blocklist

import (
	"errors"
	"io/fs"
	"os"
	"sync"
	"time"
)

// Source hands out the current version of a list. *Reloading implements it,
// and so does Static (a list that never changes).
type Source interface {
	Current() *List
}

// Static is a Source for a list that was loaded once.
type Static struct{ L *List }

func (s Static) Current() *List { return s.L }

// Reloading is a list file that picks up edits while trafficam runs, so the
// user never has to restart the watcher after changing their watch or ignore
// list.
//
// It checks the file's size and modification time at most once every
// CheckEvery (default 2 s). A missing file is an empty list. If an edit has a
// mistake in it, the previous good version is kept and OnError is told, so a
// typo can never switch protection off.
type Reloading struct {
	Path       string
	CheckEvery time.Duration
	OnError    func(error)
	Now        func() time.Time // for tests

	mu        sync.Mutex
	cur       *List
	lastCheck time.Time
	modTime   time.Time
	size      int64
	exists    bool
	loaded    bool
}

// NewReloading loads path now and returns an error only if the file exists
// and cannot be parsed (a missing file is fine: it means "no rules yet").
func NewReloading(path string) (*Reloading, error) {
	r := &Reloading{Path: path}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Current returns the list as of the last check. Nil-safe callers can use the
// result directly (a nil *List matches nothing).
func (r *Reloading) Current() *List {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	every := r.CheckEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	if t := now(); !r.loaded || t.Sub(r.lastCheck) >= every {
		r.lastCheck = t
		if err := r.reloadLocked(); err != nil && r.OnError != nil {
			r.OnError(err)
		}
	}
	return r.cur
}

func (r *Reloading) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

func (r *Reloading) reloadLocked() error {
	st, err := os.Stat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		if r.exists || !r.loaded {
			r.cur, r.exists, r.loaded = New(), false, true
		}
		return nil
	}
	if err != nil {
		return err
	}
	if r.loaded && r.exists && st.ModTime().Equal(r.modTime) && st.Size() == r.size {
		return nil // unchanged
	}
	l, err := Load(r.Path)
	if err != nil {
		// Remember this version so the same broken file is reported once,
		// not every two seconds; keep the last good list.
		r.modTime, r.size, r.exists = st.ModTime(), st.Size(), true
		return err
	}
	r.cur, r.modTime, r.size, r.exists, r.loaded = l, st.ModTime(), st.Size(), true, true
	return nil
}
