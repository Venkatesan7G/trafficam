package trustos

import (
	"testing"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func TestDefaultParsesAndMatches(t *testing.T) {
	l := Default()
	if l.Len() == 0 {
		t.Fatal("empty default list")
	}
	cases := []struct {
		goos string
		p    event.Program
		want bool
	}{
		{"windows", event.Program{Path: `c:\windows\system32\SVCHOST.exe`, Signer: "Microsoft Windows", Service: "wuauserv"}, true},
		{"windows", event.Program{Path: `C:\Windows\System32\svchost.exe`, Signer: "Microsoft Windows", Service: "BITS"}, false}, // BITS is abused for downloads
		{"windows", event.Program{Path: `C:\Windows\System32\svchost.exe`, Signer: "untrusted:Microsoft Windows", Service: "wuauserv"}, false},
		{"windows", event.Program{Path: `C:\Users\me\svchost.exe`, Signer: "Microsoft Windows", Service: "wuauserv"}, false},
		{"windows", event.Program{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Signer: "Microsoft Windows"}, false},
		{"windows", event.Program{Path: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`}, true},
		{"windows", event.Program{Path: `C:\ProgramData\Microsoft\Windows Defender\Platform\x\y\MsMpEng.exe`}, false},
		{"linux", event.Program{Path: "/usr/lib/systemd/systemd-timesyncd", Service: "systemd-timesyncd.service"}, true},
		{"linux", event.Program{Path: "/tmp/systemd-timesyncd", Service: "systemd-timesyncd.service"}, false},
		{"linux", event.Program{Path: "/usr/lib/systemd/systemd-timesyncd", Service: "evil.service"}, false},
		{"linux", event.Program{Path: `C:\Windows\System32\svchost.exe`, Signer: "Microsoft Windows", Service: "wuauserv"}, false},
	}
	for _, c := range cases {
		if got := l.match(c.goos, c.p); got != c.want {
			t.Errorf("%s %+v: got %v want %v", c.goos, c.p, got, c.want)
		}
	}
}

func TestRejectsBadLists(t *testing.T) {
	for _, s := range []string{
		`{"format":2,"programs":[]}`,
		`{"format":1,"programs":[{"os":"linux"}]}`,
		`{"format":1,"programs":[{"os":"linux","path":"/usr/**"}]}`,
		`{"format":1,"programs":[{"os":"linux","path":"/x","extra":1}]}`,
	} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestNilListTrustsNothing(t *testing.T) {
	var l *List
	if l.Trusted(event.Program{Path: "/usr/sbin/chronyd"}) {
		t.Fatal("nil list trusted something")
	}
}
