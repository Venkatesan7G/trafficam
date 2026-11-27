package notify

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/Venkatesan7G/trafficam/internal/store"
)

func TestCleanStripsTricks(t *testing.T) {
	got := Clean("evil\u202Eexe.com\nline2\x00\x07", 100)
	if strings.ContainsAny(got, "\u202E\n\x00\x07") || got != "evilexe.com line2" {
		t.Fatalf("%q", got)
	}
	if got := Clean(strings.Repeat("a", 50), 10); got != strings.Repeat("a", 10)+"…" {
		t.Fatalf("%q", got)
	}
}

func TestForAlert(t *testing.T) {
	n := ForAlert(store.Alert{Program: "svchost.exe", Service: "Dnscache", Host: "x.example", Proto: "tcp", Port: 443, Dir: "out",
		Country: "NL", Reasons: []string{"a", "b", "c", "d"}})
	if n.Title != "svchost.exe (Dnscache) contacted x.example" || !strings.Contains(n.Body, "+2 more") || !strings.Contains(n.Body, "TCP port 443, NL") {
		t.Fatalf("%+v", n)
	}
}

// A hostile host name must stay text: valid XML, and nothing that could end
// the PowerShell here-string or run a command.
func TestToastIsSafeWithHostileText(t *testing.T) {
	evil := `a'@); Start-Process calc; @'</text><x>&` + "\n'@\nrm -r C:\\"
	n := Note{Title: evil, Body: evil + "\n" + evil, OpenURL: "http://127.0.0.1:5555/?t=abc"}
	x := toastXML(n)
	if err := xml.Unmarshal([]byte(x), new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("toast XML invalid: %v\n%s", err, x)
	}
	if strings.Contains(x, "\n") || strings.Contains(x, "<x>") {
		t.Fatalf("XML not escaped: %s", x)
	}
	s := toastScript(n)
	// The only lines starting with '@ is the real terminator.
	if c := strings.Count(s, "\n'@"); c != 1 {
		t.Fatalf("here-string terminator appears %d times", c)
	}
	if _, err := base64.StdEncoding.DecodeString(encodePS(s)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(toastXML(Note{Title: "x", OpenURL: "file:///C:/evil.exe"}), "launch") {
		t.Fatal("non-local URL accepted as click target")
	}
}

func TestTamperNote(t *testing.T) {
	n := Tamper("Key file replaced\nThe key was changed at 10:00")
	if n.Urgency != Critical || !strings.Contains(n.Title, "Key file replaced") {
		t.Fatalf("%+v", n)
	}
}
