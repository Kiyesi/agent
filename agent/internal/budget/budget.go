// Package budget keeps the agent within what it may use on a customer's
// server. Each minute it reads the agent's own memory and CPU, and its
// service's memory and limit as systemd counts them (only what cannot be
// freed: not cached files). Close to the limit it is "tight", and the
// optional work (language packages, the vulnerability scan, reading logs)
// skips its turn until it is comfortable again. The agent must never be
// what slows a server.
package budget

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limits: the agent's own memory, and a share of its service's limit.
const (
	TightBytes = 120 << 20
	TightShare = 0.75
)

// Use is one minute of the agent's own use, as it is sent.
type Use struct {
	MemoryBytes     uint64   `json:"memory_bytes"`
	CPUPercent      *float64 `json:"cpu_percent"`
	ServiceBytes    uint64   `json:"service_bytes,omitempty"`
	ServiceMaxBytes uint64   `json:"service_max_bytes,omitempty"`
	Skipped         []string `json:"skipped,omitempty"`
}

// The optional work that skips its turn when the agent is tight.
const (
	Languages       = "languages"
	Vulnerabilities = "vulnerabilities"
	Logs            = "logs"
)

var (
	mu      sync.Mutex
	tight   bool
	paused  = map[string]bool{}
	skipped = map[string]bool{}
	// Root is where /proc and /sys are read; tests replace it.
	Root = "/"
	last struct {
		at    time.Time
		ticks uint64
	}
)

// Tight says whether optional work should skip its turn now.
func Tight() bool {
	mu.Lock()
	defer mu.Unlock()
	return tight
}

// Skip asks whether the named optional work must skip its turn: when the
// agent is tight, or when the service paused it. The minute's report says it skipped.
func Skip(name string) bool {
	mu.Lock()
	defer mu.Unlock()
	skip := tight || paused[name]
	if skip {
		skipped[name] = true
	}
	return skip
}

// Pause is the service's remote off switch: the named optional work is
// paused on this agent until a later reply leaves it out.
func Pause(names []string) {
	mu.Lock()
	defer mu.Unlock()
	paused = map[string]bool{}
	for _, n := range names {
		if n == Languages || n == Vulnerabilities || n == Logs {
			paused[n] = true
		}
	}
}

// Measure reads this minute's use, decides whether the agent is tight, and
// hands back what was skipped since the last minute.
func Measure(now time.Time) *Use {
	u := &Use{MemoryBytes: rss()}
	if t, ok := cpuTicks(); ok {
		mu.Lock()
		if !last.at.IsZero() && now.After(last.at) && t >= last.ticks {
			p := float64(t-last.ticks) / 100 / now.Sub(last.at).Seconds() * 100
			p = float64(int(p*10)) / 10
			u.CPUPercent = &p
		}
		last.at, last.ticks = now, t
		mu.Unlock()
	}
	u.ServiceBytes, u.ServiceMaxBytes = service()
	mu.Lock()
	tight = u.MemoryBytes > TightBytes ||
		(u.ServiceMaxBytes > 0 && float64(u.ServiceBytes) > TightShare*float64(u.ServiceMaxBytes))
	for name := range skipped {
		u.Skipped = append(u.Skipped, name)
	}
	skipped = map[string]bool{}
	mu.Unlock()
	return u
}

func read(p string) []byte {
	b, _ := os.ReadFile(path.Join(Root, p)) // #nosec G304 -- fixed paths under /proc and /sys
	return b
}

// rss is the agent's resident memory, from /proc/self/status.
func rss() uint64 {
	sc := bufio.NewScanner(bytes.NewReader(read("proc/self/status")))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				kb, _ := strconv.ParseUint(f[0], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

// cpuTicks is the agent's CPU time so far, in clock ticks (user and system).
func cpuTicks() (uint64, bool) {
	s := string(read("proc/self/stat"))
	// The command name can hold spaces: the fields start after its ")".
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 13 {
		return 0, false
	}
	u, err1 := strconv.ParseUint(f[11], 10, 64)
	k, err2 := strconv.ParseUint(f[12], 10, 64)
	return u + k, err1 == nil && err2 == nil
}

// service is the memory the agent's service holds that cannot be freed
// (anon and shared memory, not cached files), and its limit; zeros when
// not under systemd with cgroup v2, or with no limit.
func service() (held, max uint64) {
	var group string
	for _, line := range strings.Split(string(read("proc/self/cgroup")), "\n") {
		if g, ok := strings.CutPrefix(line, "0::"); ok {
			group = strings.TrimSpace(g)
		}
	}
	if group == "" || strings.Contains(group, "..") {
		return 0, 0
	}
	dir := path.Join("sys/fs/cgroup", group)
	if v := strings.TrimSpace(string(read(path.Join(dir, "memory.max")))); v != "" && v != "max" {
		max, _ = strconv.ParseUint(v, 10, 64)
	}
	sc := bufio.NewScanner(bytes.NewReader(read(path.Join(dir, "memory.stat"))))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && (f[0] == "anon" || f[0] == "shmem") {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			held += n
		}
	}
	return held, max
}
