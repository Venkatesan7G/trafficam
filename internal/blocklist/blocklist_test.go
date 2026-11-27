package blocklist

import (
	"testing"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func TestMatching(t *testing.T) {
	l := New()
	for _, s := range []string{"# comment", "Evil.Example.", "203.0.113.7", "198.51.100.0/24 curl", ""} {
		if err := l.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("len=%d", l.Len())
	}
	cases := []struct {
		m    event.Minute
		want bool
	}{
		{event.Minute{Host: "a.b.evil.example"}, true},
		{event.Minute{Host: "notevil.example"}, false}, // suffix must be on a label boundary
		{event.Minute{Host: "x.org", RemoteIP: "203.0.113.7"}, true},
		{event.Minute{Host: "198.51.100.9", Program: event.Program{Name: "curl"}}, true},
		{event.Minute{Host: "198.51.100.9", Program: event.Program{Name: "firefox"}}, false},
	}
	for i, c := range cases {
		if _, got := l.Match(c.m); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
	var nilList *List
	if nilList.IsMatch(event.Minute{Host: "x"}) {
		t.Fatal("nil list matched")
	}
	if l.Add("a b c") == nil {
		t.Fatal("bad line accepted")
	}
}

func TestWholeProgramAndService(t *testing.T) {
	l := New()
	for _, s := range []string{"* backupd", "* wuauserv", "pool.ntp.org chronyd.service"} {
		if err := l.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := New().Add("*"); err == nil {
		t.Fatal("bare * accepted")
	}
	cases := []struct {
		m    event.Minute
		want bool
	}{
		{event.Minute{Host: "anything.example", Program: event.Program{Name: "backupd"}}, true},
		{event.Minute{Host: "anything.example", Program: event.Program{Name: "firefox"}}, false},
		{event.Minute{Host: "x.example", Program: event.Program{Name: "svchost.exe", Service: "BITS,wuauserv"}}, true},
		{event.Minute{Host: "x.example", Program: event.Program{Name: "svchost.exe", Service: "Dnscache"}}, false},
		{event.Minute{Host: "pool.ntp.org", Program: event.Program{Name: "chronyd", Service: "chronyd.service"}}, true},
	}
	for i, c := range cases {
		if _, got := l.Match(c.m); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}
