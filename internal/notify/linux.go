//go:build linux

package notify

import (
	"fmt"
	"html"
	"os/exec"
	"sync"

	"github.com/godbus/dbus/v5"
)

const (
	fdoDest  = "org.freedesktop.Notifications"
	fdoPath  = "/org/freedesktop/Notifications"
	fdoIface = "org.freedesktop.Notifications"
)

// New returns the notifier for this system.
func New() Desktop { return &linuxDesktop{} }

type linuxDesktop struct {
	mu   sync.Mutex
	conn *dbus.Conn
	urls map[uint32]string // notification id -> URL to open on click
	sub  bool
}

func (*linuxDesktop) Name() string { return "freedesktop notifications (D-Bus)" }

func (d *linuxDesktop) bus() (*dbus.Conn, error) {
	if d.conn != nil && d.conn.Connected() {
		return d.conn, nil
	}
	c, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("no desktop session bus (are you logged in to a desktop?): %w", err)
	}
	d.conn, d.sub, d.urls = c, false, map[uint32]string{}
	return c, nil
}

func (d *linuxDesktop) Check() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := d.bus()
	if err != nil {
		return err
	}
	var name, vendor, version, spec string
	if err := c.Object(fdoDest, fdoPath).Call(fdoIface+".GetServerInformation", 0).Store(&name, &vendor, &version, &spec); err != nil {
		return fmt.Errorf("the desktop has no notification service: %w", err)
	}
	return nil
}

func (d *linuxDesktop) Show(n Note) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := d.bus()
	if err != nil {
		return err
	}
	urgency := byte(1)
	icon := "dialog-warning"
	timeout := int32(-1) // server default
	if n.Urgency == Critical {
		urgency, icon, timeout = 2, "dialog-error", 0 // 0 = until dismissed
	}
	var actions []string
	if n.OpenURL != "" {
		actions = []string{"default", "Open trafficam"}
		d.listen(c)
	}
	// The body may be shown with simple HTML markup, so escape it.
	var id uint32
	err = c.Object(fdoDest, fdoPath).Call(fdoIface+".Notify", 0,
		"trafficam", uint32(0), icon, n.Title, html.EscapeString(n.Body), actions,
		map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgency), "category": dbus.MakeVariant("network")},
		timeout).Store(&id)
	if err == nil && n.OpenURL != "" {
		d.urls[id] = n.OpenURL
	}
	return err
}

// listen opens the trafficam window when a notification is clicked.
func (d *linuxDesktop) listen(c *dbus.Conn) {
	if d.sub {
		return
	}
	if err := c.AddMatchSignal(dbus.WithMatchInterface(fdoIface), dbus.WithMatchMember("ActionInvoked")); err != nil {
		return
	}
	d.sub = true
	ch := make(chan *dbus.Signal, 8)
	c.Signal(ch)
	go func() {
		for s := range ch {
			if s.Name != fdoIface+".ActionInvoked" || len(s.Body) < 1 {
				continue
			}
			id, _ := s.Body[0].(uint32)
			d.mu.Lock()
			u, ok := d.urls[id]
			d.mu.Unlock()
			if ok && isLocalURL(u) {
				exec.Command("xdg-open", u).Start()
			}
		}
	}()
}
