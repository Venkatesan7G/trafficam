//go:build windows

package keyseal

const isWindows = true

// syncDir is a no-op: Windows has no directory fsync; MoveFileEx is durable
// enough once the file data itself was flushed.
func syncDir(string) {}
