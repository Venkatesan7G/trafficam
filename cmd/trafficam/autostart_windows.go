//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// setAutostart adds or removes the agent from your own (not every user's)
// list of programs started at sign-in.
func setAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue("trafficam-agent"); err != nil && err != registry.ErrNotExist {
			return err
		}
		fmt.Println("the trafficam agent will no longer start at sign-in")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := k.SetStringValue("trafficam-agent", `"`+exe+`" agent`); err != nil {
		return err
	}
	fmt.Println("the trafficam agent will start at sign-in")
	return nil
}

func autostartEnabled() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, nil
	}
	defer k.Close()
	_, _, err = k.GetStringValue("trafficam-agent")
	return err == nil, nil
}

// openBrowser opens a local trafficam link in the user's default browser.
func openBrowser(u string) error {
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", u).Start()
}

const accessHint = "Run this as the signed-in user, not from another account."
