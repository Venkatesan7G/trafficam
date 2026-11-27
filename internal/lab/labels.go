package lab

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// LabelEntry is one line of a labels file, written by the VM attack scripts
// (lab/vm) while they run a real attack scenario:
//
//	{"id":"beacon","kind":"beacon","start":"2026-11-28T10:00:00Z","end":"2026-11-28T16:00:00Z","program":"curl","host":"10.0.0.9"}
//
// A recorded row belongs to the attack when its minute falls inside
// [start, end + 2 min], its program name or path contains Program, and (if
// Host is set) its host contains Host. Matching is case-insensitive.
type LabelEntry struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	What    string    `json:"what,omitempty"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Program string    `json:"program"`
	Host    string    `json:"host,omitempty"`
}

// ApplyLabels reads a labels file and marks the matching rows of d.
func ApplyLabels(path string, d *Data) (Labels, []Attack, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var entries []LabelEntry
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e LabelEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %v", path, n, err)
		}
		if e.ID == "" || e.Program == "" || e.Start.IsZero() || e.End.Before(e.Start) {
			return nil, nil, fmt.Errorf("%s:%d: need id, program, start and an end after start", path, n)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	labels := make(Labels, len(d.Rows))
	attacks := make([]Attack, len(entries))
	for k, e := range entries {
		attacks[k] = Attack{ID: e.ID, Kind: e.Kind, What: e.What, Start: e.Start, Program: e.Program}
	}
	for i, m := range d.Rows {
		for k, e := range entries {
			if m.Start.Before(e.Start.Truncate(time.Minute)) || m.Start.After(e.End.Add(2*time.Minute)) {
				continue
			}
			p := strings.ToLower(e.Program)
			if !strings.Contains(strings.ToLower(m.Program.Name), p) && !strings.Contains(strings.ToLower(m.Program.Key()), p) {
				continue
			}
			if e.Host != "" && !strings.Contains(strings.ToLower(m.Host), strings.ToLower(e.Host)) {
				continue
			}
			if labels[i] == "" {
				labels[i] = e.ID
				attacks[k].Rows++
			}
		}
	}
	for _, a := range attacks {
		if a.Rows == 0 {
			return nil, nil, fmt.Errorf("label %q matched no recorded rows: was trafficam running, and do the program and host match?", a.ID)
		}
	}
	return labels, attacks, nil
}
