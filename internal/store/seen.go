package store

import (
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// Seen is the long-term memory of one (program, destination) pair. It is the
// raw material for the baseline rules and survives pruning of old minute rows.
type Seen struct {
	First, Last time.Time
	Days        int // distinct UTC days with contact
	Minutes     int // minute rows with contact
}

// SeenKey identifies a pair.
type SeenKey struct{ Prog, Host string }

// KeyOf builds the key for a row.
func KeyOf(m event.Minute) SeenKey { return SeenKey{m.Program.Key(), m.Host} }

// SeenGet returns what is known about the given pairs. Unknown pairs are absent.
func (s *Store) SeenGet(keys []SeenKey) (map[SeenKey]Seen, error) {
	out := make(map[SeenKey]Seen, len(keys))
	st, err := s.db.Prepare(`SELECT first_seen,last_seen,days,minutes FROM seen WHERE prog_key=? AND host=?`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	for _, k := range keys {
		if _, done := out[k]; done {
			continue
		}
		var f, l int64
		var v Seen
		switch err := st.QueryRow(k.Prog, k.Host).Scan(&f, &l, &v.Days, &v.Minutes); {
		case err == nil:
			v.First, v.Last = time.Unix(f, 0).UTC(), time.Unix(l, 0).UTC()
			out[k] = v
		case isNoRows(err):
		default:
			return nil, err
		}
	}
	return out, nil
}

// SeenUpdate records contact for every row (rows must be oldest first).
func (s *Store) SeenUpdate(rows []event.Minute) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO seen(prog_key,host,first_seen,last_seen,days,last_day,minutes)
VALUES(?,?,?,?,1,?,1)
ON CONFLICT(prog_key,host) DO UPDATE SET
  first_seen = MIN(first_seen, excluded.first_seen),
  last_seen  = MAX(last_seen,  excluded.last_seen),
  days       = days + (CASE WHEN excluded.last_day > last_day THEN 1 ELSE 0 END),
  last_day   = MAX(last_day, excluded.last_day),
  minutes    = minutes + 1`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, m := range rows {
		t := m.Start.Unix()
		if _, err := st.Exec(m.Program.Key(), m.Host, t, t, t/86400); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ProgramSummary says how established a program is: when it was first seen
// and how many different destinations it has ever contacted.
func (s *Store) ProgramSummary(prog string) (first time.Time, hosts int, err error) {
	var f *int64
	err = s.db.QueryRow(`SELECT MIN(first_seen), COUNT(*) FROM seen WHERE prog_key=?`, prog).Scan(&f, &hosts)
	if err == nil && f != nil {
		first = time.Unix(*f, 0).UTC()
	}
	return
}

// SeenStats says how much has been learned so far: how many programs have
// used the network and how many (program, destination) pairs are known.
func (s *Store) SeenStats() (programs, pairs int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(DISTINCT prog_key), COUNT(*) FROM seen`).Scan(&programs, &pairs)
	return
}
