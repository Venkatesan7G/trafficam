package replay

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/collector"
	"github.com/Venkatesan7G/trafficam/internal/event"
)

func TestRecordThenReplay(t *testing.T) {
	for _, name := range []string{"c.jsonl", "c.jsonl.gz"} {
		path := filepath.Join(t.TempDir(), name)
		w, err := Create(path)
		if err != nil {
			t.Fatal(err)
		}
		src := &collector.Synthetic{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Step: time.Second, Count: 50}
		var orig []event.Flow
		(&Recorder{Inner: src, Out: w}).Run(context.Background(), func(f event.Flow) { orig = append(orig, f) })
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		var got []event.Flow
		if err := (&Player{Path: path}).Run(context.Background(), func(f event.Flow) { got = append(got, f) }); err != nil {
			t.Fatal(err)
		}
		if len(got) != 50 || got[7].Host() != orig[7].Host() || !got[7].Time.Equal(orig[7].Time) {
			t.Fatalf("%s: replay mismatch (n=%d)", name, len(got))
		}
	}
}

func TestTornTailStillReplays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.jsonl")
	w, _ := Create(path)
	(&collector.Synthetic{Start: time.Now(), Step: time.Second, Count: 5}).Run(context.Background(), func(f event.Flow) { w.Write(f) })
	w.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"v":1,"t":"2026-`) // simulated crash mid-line
	f.Close()
	n := 0
	if err := (&Player{Path: path}).Run(context.Background(), func(event.Flow) { n++ }); err != nil || n != 5 {
		t.Fatalf("err=%v n=%d", err, n)
	}
}
