//go:build windows && (amd64 || arm64)

package etw

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// procInfo answers "which program owns PID n?" with path, parent, Windows
// service name(s) and code signer, caching the answers.
//
// Where the facts come from:
//   - path:    QueryFullProcessImageNameW on the live process, or the image
//     name from the Kernel-Process start event if it has already exited
//   - parent:  the Kernel-Process start event, or a Toolhelp snapshot for
//     processes that were running before trafficam started
//   - service: the Service Control Manager's list of running services and
//     the PID each one lives in (refreshed every 30 s)
//   - signer:  WinVerifyTrust (see signer_windows.go), cached per file
//
// Safe for concurrent use (the ETW thread records process starts while the
// worker looks programs up).
type procInfo struct {
	mu       sync.Mutex
	procs    map[uint32]*procEntry
	services map[uint32]string // PID -> "ServiceA,ServiceB"
	svcAt    time.Time         // when services was last refreshed
	snapAt   time.Time         // when the Toolhelp snapshot was last read
	ppids    map[uint32]uint32 // PID -> parent PID from that snapshot
	devices  map[string]string // \Device\HarddiskVolume3 -> C:
	signers  *signerCache
}

type procEntry struct {
	path      string
	parentPID uint32
	parent    string // parent program name, filled lazily
	exited    time.Time
}

func newProcInfo() *procInfo {
	p := &procInfo{procs: map[uint32]*procEntry{}, services: map[uint32]string{}, signers: newSignerCache()}
	p.devices = dosDevices()
	return p
}

// started records a Kernel-Process start event. The image name there is an
// NT path (\Device\HarddiskVolume3\...), which we convert to C:\...
func (p *procInfo) started(ev procEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.procs[ev.PID] = &procEntry{path: p.ntToDOS(ev.Image), parentPID: ev.ParentPID}
}

// exited records a Kernel-Process stop event. The entry is kept for a
// minute because network events for a process can arrive just after it ends.
func (p *procInfo) exited(pid uint32, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.procs[pid]; e != nil {
		e.exited = now
	}
}

// sweep forgets processes that exited more than a minute ago.
func (p *procInfo) sweep(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for pid, e := range p.procs {
		if !e.exited.IsZero() && now.Sub(e.exited) > time.Minute {
			delete(p.procs, pid)
		}
	}
}

// lookup returns everything we can find out about pid.
func (p *procInfo) lookup(pid uint32) event.Program {
	switch pid {
	case 0:
		return event.Program{PID: 0, Name: "Idle"}
	case 4:
		// The kernel itself: file sharing (SMB), some HTTP.sys traffic, etc.
		return event.Program{PID: 4, Name: "System"}
	}
	p.mu.Lock()
	e := p.procs[pid]
	if e == nil {
		e = &procEntry{}
		p.procs[pid] = e
	}
	if e.path == "" || e.exited.IsZero() {
		// Ask the live process for its path; the start event can be missing
		// (process was running before us) or carry an odd NT path.
		if live := imagePath(pid); live != "" {
			e.path = live
		}
	}
	if e.parentPID == 0 {
		e.parentPID = p.parentFromSnapshotLocked(pid)
	}
	if e.parent == "" && e.parentPID != 0 {
		if pe := p.procs[e.parentPID]; pe != nil && pe.path != "" {
			e.parent = baseName(pe.path)
		} else if pp := imagePath(e.parentPID); pp != "" {
			e.parent = baseName(pp)
		}
	}
	svc := p.serviceLocked(pid)
	path, parent := e.path, e.parent
	p.mu.Unlock()

	prog := event.Program{PID: int(pid), Path: path, Name: baseName(path), Parent: parent, Service: svc}
	if prog.Name == "" {
		prog.Name = "pid-unknown" // exited before we could look, and no start event
	}
	if path != "" {
		prog.Signer = p.signers.signer(path) // slow the first time per file, then cached
	}
	return prog
}

// serviceLocked returns the service names running in pid, refreshing the
// list from the Service Control Manager when it is old or pid is not in it.
func (p *procInfo) serviceLocked(pid uint32) string {
	if s, ok := p.services[pid]; ok && time.Since(p.svcAt) < 30*time.Second {
		return s
	}
	if time.Since(p.svcAt) > 2*time.Second { // don't hammer the SCM
		if m, err := runningServices(); err == nil {
			p.services, p.svcAt = m, time.Now()
		}
	}
	return p.services[pid]
}

// parentFromSnapshotLocked finds pid's parent in a Toolhelp process
// snapshot, taking a fresh snapshot (at most every 200 ms) if pid is not in
// the last one. Needed for processes that started before trafficam did.
func (p *procInfo) parentFromSnapshotLocked(pid uint32) uint32 {
	if pp, ok := p.ppids[pid]; ok {
		return pp
	}
	if time.Since(p.snapAt) < 200*time.Millisecond {
		return 0
	}
	p.snapAt = time.Now()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	m := map[uint32]uint32{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		m[pe.ProcessID] = pe.ParentProcessID
	}
	p.ppids = m
	return m[pid]
}

// ntToDOS converts \Device\HarddiskVolume3\x to C:\x using the device map.
func (p *procInfo) ntToDOS(nt string) string {
	for dev, drive := range p.devices {
		if strings.HasPrefix(strings.ToLower(nt), strings.ToLower(dev)+`\`) {
			return drive + nt[len(dev):]
		}
	}
	return nt
}

// dosDevices maps each drive letter's NT device name back to the letter.
func dosDevices() map[string]string {
	out := map[string]string{}
	buf := make([]uint16, 512)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		d, _ := windows.UTF16PtrFromString(drive)
		n, err := windows.QueryDosDevice(d, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		out[windows.UTF16ToString(buf)] = drive
	}
	return out
}

// imagePath asks Windows for a live process's full executable path.
// PROCESS_QUERY_LIMITED_INFORMATION works even for protected processes.
func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// runningServices returns PID -> comma-separated service names for every
// running Win32 service. Several services can share one svchost.exe.
func runningServices() (map[uint32]string, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(scm)
	var need, count, resume uint32
	buf := make([]byte, 64*1024)
	names := map[uint32][]string{}
	for {
		err = windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32,
			windows.SERVICE_ACTIVE, &buf[0], uint32(len(buf)), &need, &count, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return nil, err
		}
		list := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
		for _, s := range list {
			if s.ServiceStatusProcess.ProcessId != 0 {
				pid := s.ServiceStatusProcess.ProcessId
				names[pid] = append(names[pid], windows.UTF16PtrToString(s.ServiceName))
			}
		}
		if err == nil {
			break
		}
		if need > uint32(len(buf)) {
			buf = make([]byte, need)
		}
	}
	out := make(map[uint32]string, len(names))
	for pid, n := range names {
		sort.Strings(n)
		out[pid] = strings.Join(n, ",")
	}
	return out, nil
}

func baseName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
