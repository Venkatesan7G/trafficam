//go:build windows

package main

import (
	"fmt"
	"os"

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
