package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// AlertState is what the user has done with an alert.
type AlertState string

const (
	AlertNew   AlertState = "new"   // not looked at yet
	AlertOK    AlertState = "ok"    // the user pressed OK ("I know, that's fine")
	AlertMuted AlertState = "muted" // the user pressed "don't show again"
)

// Alert is one stored alert. It copies the fields of the minute row it is
// about, so it can still be shown after old minute rows are pruned.
type Alert struct {
	ID       int64      `json:"id"`
	At       time.Time  `json:"at"`
	Start    time.Time  `json:"start"`
	ProgKey  string     `json:"prog_key"`
	Program  string     `json:"program"`
	Path     string     `json:"path,omitempty"`
	Service  string     `json:"service,omitempty"`
	Proto    string     `json:"proto"`
	Dir      string     `json:"dir"`
	Host     string     `json:"host"`
	RemoteIP string     `json:"ip,omitempty"`
	Port     uint16     `json:"port"`
	ASN      uint32     `json:"asn,omitempty"`
	Country  string     `json:"country,omitempty"`
	Score    float64    `json:"score"`
	Reasons  []string   `json:"reasons"`
	Phase    string     `json:"phase,omitempty"`
	State    AlertState `json:"state"`
	StateAt  time.Time  `json:"state_at,omitempty"`
	// Count is how many times this alert was raised while it was still
	// unread; LastAt is the latest of those. Repeats do not create new
	// alerts, so a watched destination contacted every minute is one alert.
	Count  int       `json:"count"`
	LastAt time.Time `json:"last_at"`
}

const alertCols = `id,at,start,prog_key,prog_name,prog_path,prog_svc,proto,dir,host,remote_ip,port,asn,country,score,reasons,phase,state,state_at,count,last_at`

// RepeatWindow: an unread alert for the same program, destination, port and
// direction raised within this long absorbs a new one instead of adding a row.
const RepeatWindow = 24 * time.Hour

// AlertAdd stores an alert and returns it with its ID filled in. If the same
// alert (program, destination, port, direction) is still unread and was
// raised in the last RepeatWindow, that alert's count goes up instead and
// isNew is false.
func (s *Store) AlertAdd(a Alert) (stored Alert, isNew bool, err error) {
	var id int64
	err = s.db.QueryRow(`SELECT id FROM alerts WHERE prog_key=? AND host=? AND port=? AND dir=? AND state='new' AND at >= ?
ORDER BY id DESC LIMIT 1`, a.ProgKey, a.Host, int(a.Port), a.Dir, a.At.Add(-RepeatWindow).Unix()).Scan(&id)
	switch {
	case err == nil:
		if _, err = s.db.Exec(`UPDATE alerts SET count=count+1, last_at=MAX(last_at, ?), score=MAX(score, ?) WHERE id=?`,
			a.At.Unix(), a.Score, id); err != nil {
			return a, false, err
		}
		stored, err = s.AlertGet(id)
		return stored, false, err
	case !isNoRows(err):
		return a, false, err
	}
	stored, err = s.alertInsert(a)
	return stored, err == nil, err
}

func (s *Store) alertInsert(a Alert) (Alert, error) {
	if a.State == "" {
		a.State = AlertNew
	}
	if a.Reasons == nil {
		a.Reasons = []string{}
	}
	reasons, err := json.Marshal(a.Reasons)
	if err != nil {
		return a, err
	}
	r, err := s.db.Exec(`INSERT INTO alerts(at,start,prog_key,prog_name,prog_path,prog_svc,proto,dir,host,remote_ip,port,asn,country,score,reasons,phase,state,state_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		a.At.Unix(), a.Start.Unix(), a.ProgKey, a.Program, a.Path, a.Service, a.Proto, a.Dir, a.Host, a.RemoteIP,
		int(a.Port), a.ASN, a.Country, a.Score, string(reasons), a.Phase, string(a.State))
	if err != nil {
		return a, err
	}
	a.ID, err = r.LastInsertId()
	a.Count, a.LastAt = 1, a.At
	if err == nil {
		_, err = s.db.Exec(`UPDATE alerts SET last_at=at WHERE id=?`, a.ID)
	}
	return a, err
}

// AlertCountSince counts alerts raised at or after t.
func (s *Store) AlertCountSince(t time.Time) (n int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE at >= ?`, t.Unix()).Scan(&n)
	return
}

// AlertQuery selects alerts. Zero values mean "no filter".
type AlertQuery struct {
	AfterID int64      // only alerts with a larger ID (for "what's new since")
	Since   time.Time  // only alerts raised at or after this time
	State   AlertState // only alerts in this state
	Limit   int        // at most this many (default 200, newest last)
	Newest  bool       // return the newest Limit alerts instead of the oldest
}

// Alerts returns alerts in ID order (oldest first).
func (s *Store) Alerts(q AlertQuery) ([]Alert, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	where, args := "id > ?", []any{q.AfterID}
	if !q.Since.IsZero() {
		where += " AND at >= ?"
		args = append(args, q.Since.Unix())
	}
	if q.State != "" {
		where += " AND state = ?"
		args = append(args, string(q.State))
	}
	order := "id ASC"
	if q.Newest {
		order = "id DESC"
	}
	rows, err := s.db.Query(`SELECT `+alertCols+` FROM alerts WHERE `+where+` ORDER BY `+order+` LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if q.Newest { // back to oldest first
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, rows.Err()
}

// AlertGet returns one alert.
func (s *Store) AlertGet(id int64) (Alert, error) {
	a, err := scanAlert(s.db.QueryRow(`SELECT `+alertCols+` FROM alerts WHERE id = ?`, id))
	if isNoRows(err) {
		return a, fmt.Errorf("store: no alert %d", id)
	}
	return a, err
}

// AlertSetState records what the user did with an alert.
func (s *Store) AlertSetState(id int64, st AlertState, at time.Time) error {
	r, err := s.db.Exec(`UPDATE alerts SET state=?, state_at=? WHERE id=?`, string(st), at.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return fmt.Errorf("store: no alert %d", id)
	}
	return nil
}

// AlertCounts returns how many alerts are in each state.
func (s *Store) AlertCounts() (map[AlertState]int, error) {
	rows, err := s.db.Query(`SELECT state, COUNT(*) FROM alerts GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[AlertState]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[AlertState(st)] = n
	}
	return out, rows.Err()
}

// AlertsPruneBefore deletes alerts raised before t.
func (s *Store) AlertsPruneBefore(t time.Time) (int64, error) {
	r, err := s.db.Exec(`DELETE FROM alerts WHERE at < ?`, t.Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func scanAlert(r interface{ Scan(...any) error }) (Alert, error) {
	var (
		a                          Alert
		at, start, stateAt, lastAt int64
		port                       int
		reasons, state             string
	)
	err := r.Scan(&a.ID, &at, &start, &a.ProgKey, &a.Program, &a.Path, &a.Service, &a.Proto, &a.Dir, &a.Host,
		&a.RemoteIP, &port, &a.ASN, &a.Country, &a.Score, &reasons, &a.Phase, &state, &stateAt, &a.Count, &lastAt)
	if err != nil {
		return a, err
	}
	a.At, a.Start = time.Unix(at, 0).UTC(), time.Unix(start, 0).UTC()
	if stateAt != 0 {
		a.StateAt = time.Unix(stateAt, 0).UTC()
	}
	a.Port, a.State, a.LastAt = uint16(port), AlertState(state), time.Unix(lastAt, 0).UTC()
	if err := json.Unmarshal([]byte(reasons), &a.Reasons); err != nil {
		a.Reasons = []string{reasons}
	}
	return a, nil
}
