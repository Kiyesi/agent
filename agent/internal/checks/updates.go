package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type updatesCheck struct{}

func (updatesCheck) ID() string { return "updates" }

// aptNeeds is the memory limit under which apt-get is not started.
const aptNeeds = 192 << 20

// ownMemoryLimit is the memory limit of this program's own control group,
// such as the agent's service, or 0 when there is none or it cannot be read.
func ownMemoryLimit(fsys fs.FS) int64 {
	data, err := fs.ReadFile(fsys, "proc/self/cgroup")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2 has one line, "0::/system.slice/kiyesi.service".
		path, ok := strings.CutPrefix(line, "0::/")
		if !ok {
			continue
		}
		raw, err := fs.ReadFile(fsys, strings.TrimSuffix("sys/fs/cgroup/"+path, "/")+"/memory.max")
		if err != nil {
			return 0
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return 0 // "max": no limit
		}
		return n
	}
	return 0
}

// statePrefix marks the update dates in the scan's state file.
const statePrefix = "security-update/"

func (updatesCheck) Run(ctx context.Context, env *Env) Result {
	if !env.Sys.Exec.Has("apt-get") {
		return Skip("no-apt", nil)
	}
	// apt-get needs about 120 MB. Under the 64 MB limit of agents set up
	// before 0.39.5, the kernel kills it or it runs out of time, so the
	// check says how to raise the limit instead of starting it.
	if limit := ownMemoryLimit(env.Sys.FS); limit > 0 && limit < aptNeeds {
		return Skip("memory-limit", nil)
	}
	now := env.Sys.Now()
	print := aptPrint(env.Sys.FS)
	pending, ok := lastApt(env, print, now)
	if !ok {
		// -s simulates: apt prints what it would install and changes nothing.
		out, err := env.Sys.Exec.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
		dropAptCache(env.Sys.FS)
		if err != nil {
			return Failed(err)
		}
		pending = securityUpdates(out)
	}

	// apt does not record when an update appeared, so the scan notes the
	// day it first sees each one.
	limit := time.Duration(env.Cfg.Limits.UpdateDays) * 24 * time.Hour
	old := 0
	err := env.EditState(func(state map[string]string) {
		if !ok {
			state[aptPrintKey] = print
			state[aptAtKey] = now.UTC().Format(time.RFC3339)
			state[aptPendingKey] = strings.Join(pending, ",")
		}
		// Updates no longer waiting are forgotten; the rest keep their first day.
		for k := range state {
			if strings.HasPrefix(k, statePrefix) && !slices.Contains(pending, strings.TrimPrefix(k, statePrefix)) {
				delete(state, k)
			}
		}
		for _, pkg := range pending {
			key := statePrefix + pkg
			first, err := time.Parse(time.RFC3339, state[key])
			if err != nil {
				first = now
			}
			state[key] = first.UTC().Format(time.RFC3339)
			if now.Sub(first) > limit {
				old++
			}
		}
	})
	if err != nil {
		return Failed(err)
	}
	vars := map[string]string{"limit": strconv.Itoa(env.Cfg.Limits.UpdateDays), "count": strconv.Itoa(old)}
	if old > 0 {
		return Fail(Found("waiting", vars))
	}
	return Pass(vars)
}

// The background agent's last apt answer, kept in the scan's state file.
const (
	aptPrintKey   = "apt/print"
	aptAtKey      = "apt/at"
	aptPendingKey = "apt/pending"
)

// aptEvery is how long the background agent reuses apt's answer while
// nothing apt reads has changed.
const aptEvery = 24 * time.Hour

// aptPrint stands for everything apt-get -s upgrade reads: the installed
// packages, the package lists and apt's own cache. Only their sizes and
// dates are read, never their contents.
func aptPrint(fsys fs.FS) string {
	h := sha256.New()
	stamp := func(name string) {
		if info, err := fs.Stat(fsys, name); err == nil {
			_, _ = fmt.Fprintf(h, "%s %d %d\n", name, info.Size(), info.ModTime().UnixNano())
		}
	}
	stamp("var/lib/dpkg/status")
	stamp("var/cache/apt/pkgcache.bin")
	stamp("etc/apt/sources.list")
	for _, dir := range []string{"var/lib/apt/lists", "etc/apt/sources.list.d", "etc/apt/preferences.d"} {
		entries, _ := fs.ReadDir(fsys, dir)
		for _, e := range entries {
			if e.Type().IsRegular() {
				stamp(dir + "/" + e.Name())
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// lastApt is apt's last answer, for the background agent, when nothing it
// reads has changed and it is less than a day old. apt-get rebuilds its
// cache in memory when the lists changed and it may not write it, reading
// every package list: on a small server, a few hundred megabytes from disk
// each time, so it runs only when its answer can differ. A scan by hand
// always asks apt.
func lastApt(env *Env, print string, now time.Time) ([]string, bool) {
	if env.ReuseSlowFor <= 0 || env.Sys.State == nil {
		return nil, false
	}
	state, err := env.Sys.State.Load()
	if err != nil || state[aptPrintKey] != print {
		return nil, false
	}
	at, err := time.Parse(time.RFC3339, state[aptAtKey])
	if err != nil || now.Sub(at) > aptEvery || now.Before(at) {
		return nil, false
	}
	pending := []string{}
	if v := state[aptPendingKey]; v != "" {
		pending = strings.Split(v, ",")
	}
	return pending, true
}

// dropAptCache lets go of the package lists and apt's cache files that
// apt-get just read, so they are not kept in the system's cache on the
// agent's account (see system.RootFS): opening and closing is enough.
func dropAptCache(fsys fs.FS) {
	names := []string{"var/cache/apt/pkgcache.bin", "var/cache/apt/srcpkgcache.bin", "var/lib/dpkg/status"}
	entries, _ := fs.ReadDir(fsys, "var/lib/apt/lists")
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, "var/lib/apt/lists/"+e.Name())
		}
	}
	for _, n := range names {
		if f, err := fsys.Open(n); err == nil {
			_ = f.Close()
		}
	}
}

// securityUpdates reads `apt-get -s upgrade` lines such as
// "Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])".
func securityUpdates(out []byte) []string {
	var pkgs []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if i := strings.Index(line, "("); i >= 0 && strings.Contains(strings.ToLower(line[i:]), "security") {
			pkgs = append(pkgs, f[1])
		}
	}
	sort.Strings(pkgs)
	return pkgs
}
