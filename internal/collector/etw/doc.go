// Package etw is the Windows 10/11 capture layer for trafficam.
//
// It reads Event Tracing for Windows (ETW), the logging system built into
// Windows. ETW is one-way: Windows writes events into memory buffers and we
// read them. Nothing we do (or fail to do) can slow down, change or block a
// network packet. If trafficam crashes, Windows simply throws the unread
// events away. No driver, no packet filter, no proxy.
//
// Three built-in providers are used:
//
//	Microsoft-Windows-Kernel-Network  one event per TCP/UDP send, receive,
//	                                  connect, accept, disconnect, retransmit,
//	                                  with the owning process ID and the size.
//	Microsoft-Windows-DNS-Client      one event per finished DNS lookup, with
//	                                  the name, status and answers, emitted in
//	                                  the process that asked.
//	Microsoft-Windows-Kernel-Process  process start/stop, so short-lived
//	                                  programs still get a path and parent.
//
// How the pieces fit:
//
//	ETW thread (session_windows.go)
//	  parses each event into a small struct, pushes it on a buffered channel
//	  (never waits: if the channel is full the event is counted and dropped)
//	        |
//	        v
//	worker (collector_windows.go, the Run goroutine)
//	  dnsNames   remembers which IP each process got from DNS
//	  tracker    adds up bytes per connection, emits one event.Flow per
//	             connection (or per minute for long ones)
//	  procInfo   PID -> path, parent, Windows service name, code signer
//
// Files without "_windows" in their name are plain Go with no Windows calls,
// so their logic is unit-tested on Linux too. The Windows-only parts are
// tested on GitHub's Windows runners (etw_windows_test.go), which also check
// that the event layouts we rely on really are what Windows sends.
package etw
