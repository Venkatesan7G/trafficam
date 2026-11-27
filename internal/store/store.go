// Package store keeps minute records in an encrypted SQLite database
// (SQLCipher). Everything on disk is encrypted, including the schema.
//
// The 32-byte key comes from keyseal.Provider; it is passed to SQLCipher as a
// raw key so no slow password hashing happens on every start.
package store

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4" // registers the "sqlite3" driver (cgo)

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// DBSchemaVersion is the version of the tables below (not of event.Minute).
const DBSchemaVersion = 3

// ErrCannotOpen means the file exists but the key does not unlock it: wrong
// key, corruption, or tampering. The caller decides what to do (the planned
// policy is a loud alert, then self-destruct; that lives above this package).
var ErrCannotOpen = errors.New("store: database cannot be opened with this key (wrong key, corrupt or tampered)")

// IsWrongKey reports whether err means the key positively does not unlock
// the file (SQLite "file is not a database"). Unlike ErrCannotOpen in
// general, it excludes "busy", "locked", "disk I/O error" and similar
// problems that are not evidence of tampering. The tamper response uses it.
//
// It matches SQLite's fixed message for SQLITE_NOTADB (code 26) rather than
// the driver's error type, so this package still builds without cgo.
func IsWrongKey(err error) bool {
	return err != nil && errors.Is(err, ErrCannotOpen) && strings.Contains(err.Error(), "file is not a database")
}

type Store struct{ db *sql.DB }

// Open opens (creating if needed) the encrypted database at path.
func Open(path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("store: key must be 32 bytes, got %d", len(key))
	}
	q := url.Values{}
	q.Set("_pragma_key", "x'"+hex.EncodeToString(key)+"'")
	q.Set("_pragma_cipher_page_size", "4096")
	q.Set("_busy_timeout", "5000")
	db, err := sql.Open("sqlite3", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; keeps SQLite simple and safe
	s := &Store{db: db}
	// The first real query is where a wrong key shows up.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("%w: %w", ErrCannotOpen, err)
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrations[i] upgrades the database from schema version i+1 to i+2.
// Never edit an old entry; append a new one and bump DBSchemaVersion.
var migrations = []string{
	// v1 -> v2: parent/signer/ASN/country/duration for the model, plus the
	// baseline "seen" table and the install timestamp.
	`ALTER TABLE minutes ADD COLUMN prog_parent TEXT NOT NULL DEFAULT '';
ALTER TABLE minutes ADD COLUMN prog_signer TEXT NOT NULL DEFAULT '';
ALTER TABLE minutes ADD COLUMN asn INTEGER NOT NULL DEFAULT 0;
ALTER TABLE minutes ADD COLUMN country TEXT NOT NULL DEFAULT '';
ALTER TABLE minutes ADD COLUMN dur_ms INTEGER NOT NULL DEFAULT 0;
CREATE TABLE seen (
  prog_key   TEXT    NOT NULL,
  host       TEXT    NOT NULL,
  first_seen INTEGER NOT NULL,   -- unix seconds
  last_seen  INTEGER NOT NULL,
  days       INTEGER NOT NULL,   -- number of distinct UTC days with contact
  last_day   INTEGER NOT NULL,   -- unix day number of the latest contact
  minutes    INTEGER NOT NULL,   -- number of minute rows
  PRIMARY KEY (prog_key, host)
);
CREATE INDEX seen_prog ON seen(prog_key);
INSERT OR IGNORE INTO meta(k,v) VALUES('installed_at', CAST(strftime('%s','now') AS TEXT));`,
	// v2 -> v3: the OS service a process hosts (Windows service / systemd unit).
	`ALTER TABLE minutes ADD COLUMN prog_service TEXT NOT NULL DEFAULT '';`,
}

func (s *Store) migrate() error {
	// Version 1 base tables.
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS minutes (
  id        INTEGER PRIMARY KEY,
  start     INTEGER NOT NULL,   -- unix seconds, whole minute, UTC
  prog_key  TEXT    NOT NULL,   -- program path (or name)
  prog_name TEXT    NOT NULL,
  proto     TEXT    NOT NULL,
  dir       TEXT    NOT NULL,
  host      TEXT    NOT NULL,
  remote_ip TEXT    NOT NULL,
  port      INTEGER NOT NULL,
  flows     INTEGER NOT NULL,
  packets   INTEGER NOT NULL,
  bytes_in  INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  failed    INTEGER NOT NULL,
  score     REAL,               -- NULL = not scored
  alerted   INTEGER NOT NULL DEFAULT 0,
  schema_v  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS minutes_start ON minutes(start);
CREATE INDEX IF NOT EXISTS minutes_prog  ON minutes(prog_key, start);
INSERT OR IGNORE INTO meta(k,v) VALUES('db_schema', '1');
`)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCannotOpen, err)
	}
	var v int
	var vs string
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k='db_schema'`).Scan(&vs); err != nil {
		return err
	}
	fmt.Sscan(vs, &v)
	if v > DBSchemaVersion || v < 1 {
		return fmt.Errorf("store: database schema %q is not supported by this build (expects <= %d)", vs, DBSchemaVersion)
	}
	for ; v < DBSchemaVersion; v++ { // each step in its own transaction
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v-1]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migrating schema %d->%d: %w", v, v+1, err)
		}
		if _, err := tx.Exec(`UPDATE meta SET v=? WHERE k='db_schema'`, fmt.Sprint(v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// InstalledAt is when this database was first created (the start of the
// learning ramp). For databases upgraded from v1 it is the upgrade time.
func (s *Store) InstalledAt() (time.Time, error) {
	var sec int64
	err := s.db.QueryRow(`SELECT CAST(v AS INTEGER) FROM meta WHERE k='installed_at'`).Scan(&sec)
	return time.Unix(sec, 0).UTC(), err
}

// Scored pairs a row with the scorer's result so both are stored together.
type Scored struct {
	Minute  event.Minute
	Score   *float64 // nil = unscored
	Alerted bool
}

// Insert writes a batch in one transaction.
func (s *Store) Insert(rows []Scored) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO minutes
(start,prog_key,prog_name,proto,dir,host,remote_ip,port,flows,packets,bytes_in,bytes_out,failed,score,alerted,schema_v,prog_parent,prog_signer,asn,country,dur_ms,prog_service)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rows {
		m := r.Minute
		if _, err := st.Exec(m.Start.Unix(), m.Program.Key(), m.Program.Name, string(m.Proto), string(m.Dir),
			m.Host, m.RemoteIP, int(m.Port), m.Flows, m.Packets, m.BytesIn, m.BytesOut, m.FailedCount,
			r.Score, boolInt(r.Alerted), m.V,
			m.Program.Parent, m.Program.Signer, m.ASN, m.Country, m.DurationMs, m.Program.Service); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Since returns stored rows with start >= since, oldest first. The model's
// nightly training reads its 30-day window with this.
func (s *Store) Since(since time.Time) ([]Scored, error) {
	rows, err := s.db.Query(`SELECT start,prog_key,prog_name,proto,dir,host,remote_ip,port,flows,packets,bytes_in,bytes_out,failed,score,alerted,schema_v,prog_parent,prog_signer,asn,country,dur_ms,prog_service
FROM minutes WHERE start >= ? ORDER BY start, id`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scored
	for rows.Next() {
		var (
			m               event.Minute
			start           int64
			key, proto, dir string
			port            int
			score           sql.NullFloat64
			alerted         int
		)
		if err := rows.Scan(&start, &key, &m.Program.Name, &proto, &dir, &m.Host, &m.RemoteIP, &port,
			&m.Flows, &m.Packets, &m.BytesIn, &m.BytesOut, &m.FailedCount, &score, &alerted, &m.V,
			&m.Program.Parent, &m.Program.Signer, &m.ASN, &m.Country, &m.DurationMs, &m.Program.Service); err != nil {
			return nil, err
		}
		m.Start = time.Unix(start, 0).UTC()
		// prog_key is Program.Key(): the path (or name), plus "|service" when
		// the process hosts a service. Undo that to get the path back.
		if m.Program.Service != "" {
			key = strings.TrimSuffix(key, "|"+m.Program.Service)
		}
		m.Program.Path = ""
		if key != m.Program.Name {
			m.Program.Path = key
		}
		m.Proto, m.Dir, m.Port = event.Proto(proto), event.Direction(dir), uint16(port)
		sc := Scored{Minute: m, Alerted: alerted != 0}
		if score.Valid {
			v := score.Float64
			sc.Score = &v
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// PruneBefore deletes rows older than t (keeps the database bounded).
func (s *Store) PruneBefore(t time.Time) (int64, error) {
	r, err := s.db.Exec(`DELETE FROM minutes WHERE start < ?`, t.Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
