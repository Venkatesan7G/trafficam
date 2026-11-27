package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLongestPrefixWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.csv")
	os.WriteFile(p, []byte("# test\n10.0.0.0/8,100,us\n10.1.0.0/16,200,de\n"), 0o600)
	tb, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if a, c := tb.Lookup(netip.MustParseAddr("10.1.2.3")); a != 200 || c != "DE" {
		t.Fatalf("got %d %s", a, c)
	}
	if a, c := tb.Lookup(netip.MustParseAddr("10.9.9.9")); a != 100 || c != "US" {
		t.Fatalf("got %d %s", a, c)
	}
	if a, _ := tb.Lookup(netip.MustParseAddr("8.8.8.8")); a != 0 {
		t.Fatal("unexpected match")
	}
}
