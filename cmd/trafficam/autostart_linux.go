//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// setAutostart adds or removes ~/.config/autostart/trafficam-agent.desktop,
// which every common Linux desktop runs at login.
func setAutostart(on bool) error {
	p := autostartPath()
	if p == "" {
		return fmt.Errorf("no config folder for this user")
	}
	if !on {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("the trafficam agent will no longer start at login")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Desktop-entry quoting: wrap in double quotes, escape \ " ` $.
	q := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`).Replace(exe)
	body := "[Desktop Entry]\nType=Application\nName=trafficam agent\nComment=Shows trafficam network alerts\n" +
		"Exec=\"" + q + "\" agent\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Println("the trafficam agent will start at login:", p)
	return nil
}

func autostartPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "autostart", "trafficam-agent.desktop")
}

func autostartEnabled() (bool, error) {
	_, err := os.Stat(autostartPath())
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// openBrowser opens a local trafficam link in the user's browser.
func openBrowser(u string) error { return exec.Command("xdg-open", u).Start() }

const accessHint = "If it is running, add yourself to the trafficam group: sudo groupadd -f trafficam && sudo usermod -aG trafficam $USER (then log out and in)."
