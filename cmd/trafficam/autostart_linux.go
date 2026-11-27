//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// setAutostart adds or removes ~/.config/autostart/trafficam-agent.desktop,
// which every common Linux desktop runs at login.
func setAutostart(on bool) error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	p := filepath.Join(dir, "autostart", "trafficam-agent.desktop")
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
