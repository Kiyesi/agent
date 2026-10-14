package collect

import (
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// containerUsage is a container's CPU time so far and its memory now.
type containerUsage struct {
	cpuUsec   uint64
	memBytes  uint64
	memLimit  uint64 // 0 when there is no limit
	hasCPU    bool
	hasMemory bool
}

// cgroupDirs are where Docker puts a container's counters: cgroup v2 with
// systemd or with cgroupfs, then cgroup v1.
func cgroupDirs(id string) (v2 []string, v1cpu []string, v1mem []string) {
	return []string{
		"sys/fs/cgroup/system.slice/docker-" + id + ".scope",
		"sys/fs/cgroup/docker/" + id,
	}, []string{
		"sys/fs/cgroup/cpu,cpuacct/system.slice/docker-" + id + ".scope",
		"sys/fs/cgroup/cpu,cpuacct/docker/" + id,
		"sys/fs/cgroup/cpuacct/docker/" + id,
	}, []string{
		"sys/fs/cgroup/memory/system.slice/docker-" + id + ".scope",
		"sys/fs/cgroup/memory/docker/" + id,
	}
}

func readUint(fsys fs.FS, p string) (uint64, bool) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// statField reads one "name value" line of a cgroup stat file.
func statField(fsys fs.FS, p, name string) (uint64, bool) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// readContainer reads a container's counters, cgroup v2 first. Memory is
// counted as docker stats does: without the page cache the kernel can drop.
func readContainer(fsys fs.FS, id string) containerUsage {
	var u containerUsage
	v2, v1cpu, v1mem := cgroupDirs(id)
	for _, dir := range v2 {
		if usec, ok := statField(fsys, path.Join(dir, "cpu.stat"), "usage_usec"); ok {
			u.cpuUsec, u.hasCPU = usec, true
			if cur, ok := readUint(fsys, path.Join(dir, "memory.current")); ok {
				inactive, _ := statField(fsys, path.Join(dir, "memory.stat"), "inactive_file")
				u.memBytes, u.hasMemory = cur-min(inactive, cur), true
			}
			u.memLimit, _ = readUint(fsys, path.Join(dir, "memory.max"))
			return u
		}
	}
	for _, dir := range v1cpu {
		if ns, ok := readUint(fsys, path.Join(dir, "cpuacct.usage")); ok {
			u.cpuUsec, u.hasCPU = ns/1000, true
			break
		}
	}
	for _, dir := range v1mem {
		if cur, ok := readUint(fsys, path.Join(dir, "memory.usage_in_bytes")); ok {
			inactive, _ := statField(fsys, path.Join(dir, "memory.stat"), "total_inactive_file")
			u.memBytes, u.hasMemory = cur-min(inactive, cur), true
			limit, _ := readUint(fsys, path.Join(dir, "memory.limit_in_bytes"))
			// cgroup v1 writes a huge number for "no limit".
			if limit < 1<<60 {
				u.memLimit = limit
			}
			break
		}
	}
	return u
}
