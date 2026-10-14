// Package collect takes the agent's measurements each minute: the server's
// CPU, memory, disks and network, each container's CPU and memory, requests
// from the web server's log, and events such as a restart. Like the checks,
// it only reads.
package collect

import (
	"bufio"
	"bytes"
	"io/fs"
	"strconv"
	"strings"
)

// cpuTimes are the jiffies /proc/stat counts across every core.
type cpuTimes struct{ busy, total uint64 }

// readCPU reads the first line of /proc/stat and the number of cores.
func readCPU(fsys fs.FS) (cpuTimes, int, error) {
	data, err := fs.ReadFile(fsys, "proc/stat")
	if err != nil {
		return cpuTimes{}, 0, err
	}
	var t cpuTimes
	cores := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "cpu":
			var idle uint64
			for i, v := range f[1:] {
				n, _ := strconv.ParseUint(v, 10, 64)
				// user nice system idle iowait irq softirq steal: guest time
				// is already counted in user, so stop before it.
				if i >= 8 {
					break
				}
				t.total += n
				if i == 3 || i == 4 {
					idle += n
				}
			}
			t.busy = t.total - idle
		case strings.HasPrefix(f[0], "cpu"):
			cores++
		}
	}
	return t, max(cores, 1), nil
}

// memInfo is what /proc/meminfo says, in bytes.
type memInfo struct{ total, available, swapTotal, swapFree uint64 }

func readMem(fsys fs.FS) (memInfo, error) {
	data, err := fs.ReadFile(fsys, "proc/meminfo")
	if err != nil {
		return memInfo{}, err
	}
	var m memInfo
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		n *= 1024
		switch f[0] {
		case "MemTotal:":
			m.total = n
		case "MemAvailable:":
			m.available = n
		case "SwapTotal:":
			m.swapTotal = n
		case "SwapFree:":
			m.swapFree = n
		}
	}
	return m, nil
}

// virtualNet are interfaces that only carry traffic between containers or
// back to this machine, so they would count the same bytes twice.
func virtualNet(name string) bool {
	for _, p := range []string{"lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "tun", "tap", "wg"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// netBytes are the bytes received and sent on the real interfaces.
type netBytes struct{ rx, tx uint64 }

func readNet(fsys fs.FS) (netBytes, error) {
	data, err := fs.ReadFile(fsys, "proc/net/dev")
	if err != nil {
		return netBytes{}, err
	}
	var n netBytes
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if virtualNet(name) || len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		n.rx += rx
		n.tx += tx
	}
	return n, nil
}

// readOOMKills is the number of processes the kernel has killed for memory
// since it started (/proc/vmstat, Linux 4.13 and later).
func readOOMKills(fsys fs.FS) (uint64, bool) {
	data, err := fs.ReadFile(fsys, "proc/vmstat")
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "oom_kill "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

func readLoad1(fsys fs.FS) (float64, bool) {
	data, err := fs.ReadFile(fsys, "proc/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}
