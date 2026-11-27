package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAlerts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "a.db"), key(3))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	var ids []int64
	for i := 0; i < 3; i++ {
		a, err := s.AlertAdd(Alert{At: t0.Add(time.Duration(i) * time.Hour), Start: t0, Program: "curl", ProgKey: "/usr/bin/curl",
			Host: "x.example", Port: 443, Proto: "tcp", Dir: "out", Score: 0.9, Reasons: []string{"new host", "on watch list"}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
	}
	got, err := s.Alerts(AlertQuery{AfterID: ids[0]})
	if err != nil || len(got) != 2 || got[0].ID != ids[1] || len(got[0].Reasons) != 2 || got[0].State != AlertNew {
		t.Fatalf("after: %+v %v", got, err)
	}
	if got, _ := s.Alerts(AlertQuery{Limit: 1, Newest: true}); len(got) != 1 || got[0].ID != ids[2] {
		t.Fatalf("newest: %+v", got)
	}
	if err := s.AlertSetState(ids[1], AlertOK, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.AlertSetState(999, AlertOK, t0); err == nil {
		t.Fatal("missing alert accepted")
	}
	if got, _ := s.Alerts(AlertQuery{State: AlertNew}); len(got) != 2 {
		t.Fatalf("state filter: %d", len(got))
	}
	c, _ := s.AlertCounts()
	if c[AlertNew] != 2 || c[AlertOK] != 1 {
		t.Fatalf("counts %v", c)
	}
	a, err := s.AlertGet(ids[1])
	if err != nil || a.State != AlertOK || !a.StateAt.Equal(t0) {
		t.Fatalf("get %+v %v", a, err)
	}
	if n, _ := s.AlertsPruneBefore(t0.Add(90 * time.Minute)); n != 2 {
		t.Fatalf("pruned %d", n)
	}
}
