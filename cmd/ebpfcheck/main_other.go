//go:build !linux

// Command ebpfcheck only works on Linux.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ebpfcheck needs Linux")
	os.Exit(1)
}
