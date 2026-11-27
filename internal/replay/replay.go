// Package replay records Flows to a file and plays them back.
//
// File format: one JSON object per line ("JSONL"), optionally gzip-compressed
// (chosen by a ".gz" file name). The first line is a header:
//
//	{"trafficam_replay":1,"schema":1,"created":"..."}
//
// followed by one event.Flow per line. JSONL is deliberately boring: it can be
// read with any tool, diffed, and appended to, and a truncated file (crash
// mid-write) still replays everything before the break.
//
// Recordings let us test the model and the scorer deterministically, and let
// users attach a capture to a bug report (after reviewing it: it contains
// hostnames and program paths).
package replay

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/event"
)

// FormatVersion is the version of the replay file container (not of Flow).
const FormatVersion = 1

type header struct {
	Format  int       `json:"trafficam_replay"`
	Schema  int       `json:"schema"`
	Created time.Time `json:"created"`
}

// Writer appends Flows to a replay file. Safe for concurrent use.
type Writer struct {
	mu  sync.Mutex
	f   *os.File
	gz  *gzip.Writer
	buf *bufio.Writer
}

// Create makes (or truncates) a replay file and writes the header.
func Create(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f}
	var dst io.Writer = f
	if strings.HasSuffix(path, ".gz") {
		w.gz = gzip.NewWriter(f)
		dst = w.gz
	}
	w.buf = bufio.NewWriter(dst)
	h, _ := json.Marshal(header{FormatVersion, event.SchemaVersion, time.Now().UTC()})
	w.buf.Write(h)
	w.buf.WriteByte('\n')
	return w, nil
}

// Write appends one flow.
func (w *Writer) Write(fl event.Flow) error {
	b, err := json.Marshal(fl)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(b)
	return w.buf.WriteByte('\n')
}

// Close flushes and closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.buf.Flush()
	if w.gz != nil {
		if e := w.gz.Close(); err == nil {
			err = e
		}
	}
	if e := w.f.Close(); err == nil {
		err = e
	}
	return err
}

// Recorder wraps a Collector and copies every flow it emits into a Writer.
// Use it to capture real traffic for later replay.
type Recorder struct {
	Inner collector.Collector
	Out   *Writer
}

func (r *Recorder) Name() string { return "record(" + r.Inner.Name() + ")" }

func (r *Recorder) Run(ctx context.Context, emit func(event.Flow)) error {
	return r.Inner.Run(ctx, func(fl event.Flow) {
		_ = r.Out.Write(fl) // a full disk must not stop monitoring
		emit(fl)
	})
}

// Player is a Collector that replays a recording.
type Player struct {
	Path string
	// Speed scales event-time to real time: 1 = real time, 60 = a minute per
	// second, 0 = as fast as possible (default for tests).
	Speed float64
}

func (p *Player) Name() string { return "replay(" + p.Path + ")" }

func (p *Player) Run(ctx context.Context, emit func(event.Flow)) error {
	f, err := os.Open(p.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	var src io.Reader = f
	if strings.HasSuffix(p.Path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		src = gz
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	if !sc.Scan() {
		return errors.New("replay: empty file")
	}
	var h header
	if err := json.Unmarshal(sc.Bytes(), &h); err != nil || h.Format == 0 {
		return errors.New("replay: missing or bad header")
	}
	if h.Format > FormatVersion {
		return fmt.Errorf("replay: file format %d is newer than this build supports (%d)", h.Format, FormatVersion)
	}

	var prev time.Time
	for sc.Scan() {
		var fl event.Flow
		if err := json.Unmarshal(sc.Bytes(), &fl); err != nil {
			// A torn last line from a crash is expected; stop quietly there.
			return nil
		}
		if p.Speed > 0 && !prev.IsZero() {
			if gap := fl.Time.Sub(prev); gap > 0 {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Duration(float64(gap) / p.Speed)):
				}
			}
		}
		prev = fl.Time
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		emit(fl)
	}
	return sc.Err()
}
