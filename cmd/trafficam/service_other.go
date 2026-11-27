//go:build !windows

package main

import "fmt"

// runningAsService is only true on Windows when the Service Control Manager
// started us.
func runningAsService() bool { return false }

func serviceCommand(args []string) error {
	return fmt.Errorf("the service command is for Windows; on Linux use the systemd unit")
}
