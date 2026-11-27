package lab

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/aggregate"
	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/replay"
	"github.com/Venkatesan7G/trafficam/internal/store"
)

// A minutes file holds per-minute rows exactly as the database stores them.
// It is what "trafficam export" writes and what "trafficam eval" reads. Same
// container as a replay file (JSONL, ".gz" = gzip), different header:
//
//	{"trafficam_minutes":1,"schema":3,"created":"...","installed":"..."}
//
// then one event.Minute per line. "installed" is when the exporting
// database was created; the replay uses it as the install time.
const minutesFormat = 1

type minutesHeader struct {
	Format    int       `json:"trafficam_minutes"`
	Schema    int       `json:"schema"`
	Created   time.Time `json:"created"`
	Installed time.Time `json:"installed,omitzero"`
}

// Data is a loaded recording: rows oldest first, plus the install time if
// the source knew it (zero = use the first row).
type Data struct {
	Rows      []event.Minute
	Installed time.Time
	Source    string
}

// Days is how many calendar days (UTC) the rows cover, at least 1.
func (d *Data) Days() int {
	if len(d.Rows) == 0 {
		return 0
	}
	first := d.Rows[0].Start.Truncate(24 * time.Hour)
	last := d.Rows[len(d.Rows)-1].Start.Truncate(24 * time.Hour)
	return int(last.Sub(first)/(24*time.Hour)) + 1
}

// InstallTime is when the replayed install starts learning.
func (d *Data) InstallTime() time.Time {
	// The database's install time is used unless it is after the first row
	// (a database made by replaying old data, or rows imported from elsewhere).
	if !d.Installed.IsZero() && (len(d.Rows) == 0 || !d.Installed.After(d.Rows[0].Start)) {
		return d.Installed
	}
	if len(d.Rows) > 0 {
		return d.Rows[0].Start
	}
	return time.Time{}
}

// WriteMinutes saves rows as a minutes file.
func WriteMinutes(path string, d *Data) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	var w io.Writer = f
	var gz *gzip.Writer
	if strings.HasSuffix(path, ".gz") {
		gz = gzip.NewWriter(f)
		w = gz
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	err = enc.Encode(minutesHeader{minutesFormat, event.SchemaVersion, time.Now().UTC(), d.Installed})
	for i := 0; err == nil && i < len(d.Rows); i++ {
		err = enc.Encode(&d.Rows[i])
	}
	if e := bw.Flush(); err == nil {
		err = e
	}
	if gz != nil {
		if e := gz.Close(); err == nil {
			err = e
		}
	}
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}

// Load reads a minutes file or a replay (flows) file, telling them apart by
// the header. Flows are rolled up into minutes the same way the live service
// does it.
func Load(path string) (*Data, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var src io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		src = gz
	}
	br := bufio.NewReaderSize(src, 1<<20)
	first, err := br.ReadBytes('\n')
	if err != nil && len(first) == 0 {
		return nil, fmt.Errorf("%s: empty file", path)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(first, &probe); err != nil {
		return nil, fmt.Errorf("%s: bad header: %v", path, err)
	}
	if _, ok := probe["trafficam_replay"]; ok {
		return loadFlows(path)
	}
	var h minutesHeader
	if err := json.Unmarshal(first, &h); err != nil || h.Format == 0 {
		return nil, fmt.Errorf("%s: not a trafficam minutes or replay file", path)
	}
	if h.Format > minutesFormat {
		return nil, fmt.Errorf("%s: minutes format %d is newer than this build (%d)", path, h.Format, minutesFormat)
	}
	d := &Data{Installed: h.Installed, Source: path}
	dec := json.NewDecoder(br)
	for {
		var m event.Minute
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break // a torn last line (crash mid-write) is fine
			}
			return nil, fmt.Errorf("%s: row %d: %v", path, len(d.Rows)+1, err)
		}
		d.Rows = append(d.Rows, m)
	}
	SortRows(d.Rows)
	return d, nil
}

func loadFlows(path string) (*Data, error) {
	agg := aggregate.New()
	p := &replay.Player{Path: path}
	if err := p.Run(context.Background(), agg.Add); err != nil {
		return nil, err
	}
	d := &Data{Rows: agg.Drain(), Source: path}
	SortRows(d.Rows)
	return d, nil
}

// FromStore reads every row in a trafficam database.
func FromStore(st *store.Store) (*Data, error) {
	rows, err := st.Since(time.Unix(0, 0))
	if err != nil {
		return nil, err
	}
	d := &Data{Rows: make([]event.Minute, len(rows)), Source: "database"}
	for i := range rows {
		d.Rows[i] = rows[i].Minute
	}
	if d.Installed, err = st.InstalledAt(); err != nil {
		return nil, err
	}
	SortRows(d.Rows)
	return d, nil
}

// SortRows orders rows by minute (stable, so equal minutes keep file order).
func SortRows(rows []event.Minute) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Start.Before(rows[j].Start) })
}
