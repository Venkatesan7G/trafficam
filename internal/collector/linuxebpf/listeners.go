//go:build linux

package linuxebpf

// listeners.go finds which program owns a listening TCP port by reading
// /proc. The kernel side learns this itself when a program calls listen(),
// but servers that started before trafficam (sshd, a web server...) did
// that before we were watching. So at start-up we read the existing
// listeners from /proc and hand them to the kernel side, and we use the
// same lookup as a fallback for inbound connections with no known owner.

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// listenSock is one listening socket from /proc/net/tcp or tcp6.
type listenSock struct {
	Port  uint16
	Inode uint64
}

// parseProcNetTCP returns the listening sockets in a /proc/net/tcp(6) file.
//
// Each line looks like:
//
//	sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
//	0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 ...
//
// local_address is hex IP:hex port, st 0A means LISTEN.
func parseProcNetTCP(path string) []listenSock {
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	var out []listenSock
	sc := bufio.NewScanner(fh)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err1 := strconv.ParseUint(portHex, 16, 16)
		inode, err2 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || inode == 0 {
			continue
		}
		out = append(out, listenSock{uint16(port), inode})
	}
	return out
}

// socketOwners maps socket inodes to the pid holding them, by reading the
// /proc/<pid>/fd links ("socket:[12345]"). Only inodes in want are kept.
func socketOwners(procRoot string, want map[uint64]bool) map[uint64]int {
	out := map[uint64]int{}
	pids, _ := os.ReadDir(procRoot)
	for _, d := range pids {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 64)
			if err == nil && want[ino] {
				if _, seen := out[ino]; !seen {
					out[ino] = pid
				}
			}
		}
		if len(out) == len(want) {
			break
		}
	}
	return out
}

// readStat returns a process's parent pid and comm from /proc/<pid>/stat.
// Format: "pid (comm) state ppid ...". comm may contain spaces and ")".
func readStat(procRoot string, pid int) (ppid int, comm string, ok bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, "", false
	}
	s := string(b)
	open, closeIdx := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < open {
		return 0, "", false
	}
	comm = s[open+1 : closeIdx]
	f := strings.Fields(s[closeIdx+1:])
	if len(f) < 2 {
		return 0, "", false
	}
	ppid, err = strconv.Atoi(f[1])
	return ppid, comm, err == nil
}

// listenerOwners returns port -> owner facts for every listening TCP port.
func listenerOwners(procRoot string) map[uint16]procFacts {
	socks := append(parseProcNetTCP(filepath.Join(procRoot, "net", "tcp")),
		parseProcNetTCP(filepath.Join(procRoot, "net", "tcp6"))...)
	want := map[uint64]bool{}
	for _, s := range socks {
		want[s.Inode] = true
	}
	if len(want) == 0 {
		return nil
	}
	owners := socketOwners(procRoot, want)
	out := map[uint16]procFacts{}
	for _, s := range socks {
		pid, ok := owners[s.Inode]
		if !ok {
			continue
		}
		ppid, comm, _ := readStat(procRoot, pid)
		_, pcomm, _ := readStat(procRoot, ppid)
		out[s.Port] = procFacts{PID: pid, PPID: ppid, Comm: comm, PComm: pcomm}
	}
	return out
}

// toOwner packs facts into the kernel's owner struct.
func toOwner(f procFacts) trafficamOwner {
	o := trafficamOwner{Tgid: uint32(f.PID), Ppid: uint32(f.PPID), Cgroup: f.Cgroup}
	copyComm(o.Comm[:], f.Comm)
	copyComm(o.Pcomm[:], f.PComm)
	return o
}

func copyComm(dst []int8, s string) {
	for i := 0; i < len(dst)-1 && i < len(s); i++ {
		dst[i] = int8(s[i])
	}
}
