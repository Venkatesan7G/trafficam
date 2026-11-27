//go:build linux

package notify

import (
	"bufio"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeServer plays the desktop's notification service on a private D-Bus.
type fakeServer struct {
	mu   sync.Mutex
	got  []string
	urg  []byte
	tout []int32
}

func (f *fakeServer) Notify(app string, replaces uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, summary+"|"+body)
	u, _ := hints["urgency"].Value().(byte)
	f.urg, f.tout = append(f.urg, u), append(f.tout, timeout)
	return uint32(len(f.got)), nil
}

func (f *fakeServer) GetServerInformation() (string, string, string, string, *dbus.Error) {
	return "fake", "test", "1", "1.2", nil
}

func TestLinuxNotifyOverRealDBus(t *testing.T) {
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command(daemon, "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start dbus-daemon:", err)
	}
	defer cmd.Process.Kill()
	addrCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		addrCh <- strings.TrimSpace(line)
	}()
	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Skip("dbus-daemon did not start")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)

	srv, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	fake := &fakeServer{}
	if err := srv.Export(fake, fdoPath, fdoIface); err != nil {
		t.Fatal(err)
	}
	if r, err := srv.RequestName(fdoDest, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("cannot own name", r, err)
	}

	d := New()
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	if err := d.Show(Note{Title: "curl contacted x.example", Body: "new <b>host</b>", OpenURL: "http://127.0.0.1:1/"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Show(Tamper("Key replaced\nsomething")); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.got) != 2 || fake.got[0] != "curl contacted x.example|new &lt;b&gt;host&lt;/b&gt;" {
		t.Fatalf("got %q", fake.got)
	}
	if fake.urg[1] != 2 || fake.tout[1] != 0 {
		t.Fatalf("tamper note not critical/sticky: %v %v", fake.urg, fake.tout)
	}
}
