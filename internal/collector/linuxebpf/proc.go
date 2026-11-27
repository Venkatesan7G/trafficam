//go:build linux

package linuxebpf

// proc.go turns a process id (plus the facts the kernel captured) into an
// event.Program: executable path, short name, parent and systemd unit.
//
// Nothing here needs root or eBPF, so it is unit tested on any machine by
// pointing Root at a fake /proc tree.

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// procFacts is what the kernel side tells us about a socket's owner. It is
// captured at connect/send time, so it is correct even if the process has
// already exited by the time we read the event.
type procFacts struct {
	PID    int
	PPID   int
	Comm   string // kernel's short name (max 15 chars)
	PComm  string // parent's short name
	Cgroup uint64 // cgroup v2 id
}

// procInfo is the resolved identity of one process.
type procInfo struct {
	Name   string // executable base name, e.g. "firefox"
	Path   string // full executable path, "" if unknown
	Parent string // parent's executable base name (or comm)
	Unit   string // systemd service unit, e.g. "nginx.service"; "" for desktop apps
}

// procResolver caches lookups, because a busy program opens many sockets
// and reading /proc for each one would be wasteful.
type procResolver struct {
	Root       string // "/proc" normally; a temp dir in tests
	CgroupRoot string // where cgroup v2 is mounted, e.g. "/sys/fs/cgroup"; "" = unknown
	TTL        time.Duration
	MaxEntries int
	now        func() time.Time

	mu      sync.Mutex
	cache   map[int]cachedProc
	cgPaths map[uint64]string // cgroup id -> path below CgroupRoot
	cgScan  time.Time         // last full scan of the cgroup tree
}

type cachedProc struct {
	info procInfo
	comm string // to notice a recycled pid
	at   time.Time
}

func newProcResolver(root, cgroupRoot string) *procResolver {
	return &procResolver{
		Root: root, CgroupRoot: cgroupRoot, TTL: 2 * time.Minute, MaxEntries: 8192,
		now: time.Now, cache: map[int]cachedProc{}, cgPaths: map[uint64]string{},
	}
}

// Resolve returns the identity of the process described by f.
func (r *procResolver) Resolve(f procFacts) procInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if c, ok := r.cache[f.PID]; ok && now.Sub(c.at) < r.TTL && (f.Comm == "" || c.comm == f.Comm) {
		return c.info
	}
	info := r.readProc(f)
	if len(r.cache) >= r.MaxEntries {
		// Simple bound: forget everything. Entries are cheap to rebuild.
		r.cache = map[int]cachedProc{}
	}
	r.cache[f.PID] = cachedProc{info: info, comm: f.Comm, at: now}
	return info
}

func (r *procResolver) readProc(f procFacts) procInfo {
	info := procInfo{Name: f.Comm, Parent: f.PComm}
	dir := filepath.Join(r.Root, strconv.Itoa(f.PID))

	// /proc/<pid>/exe is a symlink to the executable. It is the strongest
	// identity we have: a program can fake its name, not its path.
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		exe = strings.TrimSuffix(exe, " (deleted)") // binary replaced by an update
		info.Path = exe
		info.Name = filepath.Base(exe)
	}
	if f.PPID > 0 {
		if pexe, err := os.Readlink(filepath.Join(r.Root, strconv.Itoa(f.PPID), "exe")); err == nil {
			info.Parent = filepath.Base(strings.TrimSuffix(pexe, " (deleted)"))
		}
	}

	// The cgroup path tells us the systemd unit. Prefer /proc (exact);
	// fall back to the cgroup id the kernel gave us if the process is gone.
	cg := readCgroupV2Path(filepath.Join(dir, "cgroup"))
	if cg == "" && f.Cgroup != 0 {
		cg = r.cgroupPathByID(f.Cgroup)
	}
	info.Unit = unitFromCgroup(cg)
	return info
}

// readCgroupV2Path reads the "0::/some/path" line of /proc/<pid>/cgroup.
func readCgroupV2Path(file string) string {
	fh, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return p
		}
	}
	return ""
}

// unitFromCgroup picks the systemd service out of a cgroup path.
//
//	/system.slice/nginx.service                                  -> nginx.service
//	/user.slice/user-1000.slice/user@1000.service/app.slice/
//	      pipewire.service                                       -> pipewire.service
//	/user.slice/.../user@1000.service/app.slice/app-firefox-12.scope -> "" (a desktop app)
//
// Desktop apps get "" on purpose: their scope names contain random numbers
// and would split one program's history into many.
func unitFromCgroup(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasSuffix(p, ".scope") {
			return ""
		}
		if strings.HasSuffix(p, ".service") {
			if strings.HasPrefix(p, "user@") || strings.HasPrefix(p, "user-runtime-dir@") {
				return "" // the per-user systemd manager, not a real service
			}
			return p
		}
	}
	return ""
}

// cgroupPathByID maps a cgroup v2 id to its path. In cgroup v2 the id is
// the inode number of the cgroup's directory, so we find it by walking the
// tree. The walk is cached and repeated at most every 30 seconds.
func (r *procResolver) cgroupPathByID(id uint64) string {
	if p, ok := r.cgPaths[id]; ok {
		return p
	}
	if r.CgroupRoot == "" || r.now().Sub(r.cgScan) < 30*time.Second {
		return ""
	}
	r.cgScan = r.now()
	r.cgPaths = map[uint64]string{}
	_ = filepath.WalkDir(r.CgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			rel, _ := filepath.Rel(r.CgroupRoot, p)
			r.cgPaths[uint64(st.Ino)] = "/" + filepath.ToSlash(rel)
		}
		return nil
	})
	return r.cgPaths[id]
}

// findCgroup2Mount returns where cgroup v2 is mounted, from a mountinfo file
// (normally /proc/self/mountinfo). Modern distros use /sys/fs/cgroup; older
// "hybrid" setups use /sys/fs/cgroup/unified.
func findCgroup2Mount(mountinfo string) string {
	fh, err := os.Open(mountinfo)
	if err != nil {
		return ""
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		// Format: id parent major:minor root mountpoint opts ... - fstype source superopts
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		if f := strings.Fields(right); len(f) > 0 && f[0] == "cgroup2" {
			if lf := strings.Fields(left); len(lf) >= 5 {
				return lf[4]
			}
		}
	}
	return ""
}

// cString converts a fixed-size, NUL-padded C char array to a Go string.
func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
