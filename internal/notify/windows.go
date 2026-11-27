//go:build windows

package notify

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// New returns the notifier for this system.
func New() Desktop { return winDesktop{} }

type winDesktop struct{}

func (winDesktop) Name() string { return "Windows toast notifications" }

func (winDesktop) Check() error {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return fmt.Errorf("powershell.exe not found, which trafficam uses to show notifications: %w", err)
	}
	return nil
}

// Show runs a short, hidden PowerShell script that asks Windows to show a
// toast. The script is passed base64-encoded and contains our text only as
// escaped XML inside a single-quoted here-string, so no part of a host name
// can ever be run as a command.
func (winDesktop) Show(n Note) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-WindowStyle", "Hidden", "-EncodedCommand", encodePS(toastScript(n)))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("showing a toast: %v: %s", err, out)
	}
	return nil
}
