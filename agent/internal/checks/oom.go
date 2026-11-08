package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type oomCheck struct{}

func (oomCheck) ID() string { return "oom" }

// killedRE matches the kernel's line for a process killed for memory, both
// for the whole server and for a container's memory limit.
var killedRE = regexp.MustCompile(`Killed process (\d+) \(([^)]+)\)`)

// ownLimitRE matches the kernel's line just before a kill made by a
// service's own memory limit, naming that limit's control group and the
// process: "oom-kill:constraint=CONSTRAINT_MEMCG,...,
// oom_memcg=/system.slice/kiyesi.service,...,task=apt-get,pid=4211,...".
var ownLimitRE = regexp.MustCompile(`oom-kill:.*oom_memcg=[^,]*/kiyesi\.service,.*pid=(\d+)`)

type kill struct {
	process string
	at      time.Time
}

func (oomCheck) Run(ctx context.Context, env *Env) Result {
	now := env.Sys.Now()
	var kills []kill
	switch {
	case env.Sys.Root && env.Sys.Exec.Has("journalctl") && env.ReuseSlowFor > 0 && env.Sys.State != nil:
		var err error
		if kills, err = newKills(ctx, env, now); err != nil {
			return Failed(err)
		}
	case env.Sys.Root && env.Sys.Exec.Has("journalctl"):
		out, err := env.Sys.Exec.Run(ctx, "journalctl", "-k", "--since", "-24h", "--no-pager", "-q", "-o", "short-iso")
		dropJournalCache(env.Sys.FS)
		if err != nil {
			return Failed(err)
		}
		kills = parseKernelLog(out, now)
	default:
		// Without root, journalctl hides the kernel log, and an empty answer
		// would look like "no kills". Read kern.log if this user may.
		data, err := fs.ReadFile(env.Sys.FS, "var/log/kern.log")
		switch {
		case err == nil:
			kills = parseKernelLog(data, now)
		case errors.Is(err, fs.ErrPermission) || !env.Sys.Root:
			return NeedsRoot()
		case errors.Is(err, fs.ErrNotExist):
			return Skip("no-kernel-log", nil)
		default:
			return Failed(err)
		}
	}
	if len(kills) == 0 {
		return Pass(nil)
	}
	mem, _ := readMemInfo(env.Sys.FS)
	// One finding per process, at its latest kill.
	latest := map[string]time.Time{}
	for _, k := range kills {
		if k.at.After(latest[k.process]) {
			latest[k.process] = k.at
		}
	}
	names := make([]string, 0, len(latest))
	for p := range latest {
		names = append(names, p)
	}
	sort.Slice(names, func(i, j int) bool { return latest[names[i]].After(latest[names[j]]) })
	var found []Finding
	for _, p := range names {
		vars := map[string]string{"process": p, "time": clockText(latest[p], now), "total": bytesText(mem.Total)}
		key := "killed"
		if mem.Total > 0 && mem.SwapTotal == 0 {
			key = "killed-no-swap"
		}
		found = append(found, Found(key, vars))
	}
	return Fail(found...)
}

// parseKernelLog finds kills in the last 24 hours. It reads journalctl's
// short-iso lines and rsyslog's lines, which start with an RFC 3339 time.
// A kill made by the kiyesi service's own memory limit (the agent, or a
// program one of its checks ran) is Kiyesi's problem, not the server's,
// so it is left out.
func parseKernelLog(data []byte, now time.Time) []kill {
	var out []kill
	own := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := ownLimitRE.FindStringSubmatch(line); m != nil {
			own[m[1]] = true
			continue
		}
		m := killedRE.FindStringSubmatch(line)
		if m == nil || own[m[1]] {
			continue
		}
		stamp, _, _ := strings.Cut(line, " ")
		at, err := parseLogTime(stamp)
		if err != nil || now.Sub(at) > time24h || at.After(now.Add(time.Minute)) {
			continue
		}
		out = append(out, kill{process: m[2], at: at})
	}
	return out
}

func parseLogTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700", "2006-01-02T15:04:05.999999-07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("no time at the start of the line")
}

// The background agent's place in the kernel log and the kills it has
// seen in the last 24 hours, kept in the scan's state file.
const (
	oomCursorKey = "oom/cursor"
	oomAtKey     = "oom/at"
	oomKillsKey  = "oom/kills"
)

// cursorPrefix starts the line journalctl --show-cursor adds after the
// last entry it printed. It prints none when no entry was new.
const cursorPrefix = "-- cursor: "

type savedKill struct {
	Process string    `json:"p"`
	At      time.Time `json:"at"`
}

// newKills is the background agent's way to read the kernel log: the last
// 24 hours once, then at each scan only what came after the place it
// stopped. journalctl --since -24h reads a day of the whole system log,
// which on a busy server is gigabytes: under the service's memory limit,
// read again every 15 minutes, the kernel kept loading and throwing out
// the same files. A scan by hand still reads the 24 hours.
func newKills(ctx context.Context, env *Env, now time.Time) ([]kill, error) {
	state, err := env.Sys.State.Load()
	if err != nil {
		return nil, err
	}
	var saved []savedKill
	_ = json.Unmarshal([]byte(state[oomKillsKey]), &saved)
	since := "-24h"
	if at, err := time.Parse(time.RFC3339, state[oomAtKey]); err == nil && now.Sub(at) < time24h && !now.Before(at) {
		since = "@" + strconv.FormatInt(at.Unix(), 10)
	} else {
		saved = nil
	}
	read := func(from ...string) ([]byte, error) {
		args := append([]string{"-k"}, from...)
		args = append(args, "--show-cursor", "--no-pager", "-q", "-o", "short-iso")
		return env.Sys.Exec.Run(ctx, "journalctl", args...)
	}
	var out []byte
	err = errors.New("no place kept")
	if c := state[oomCursorKey]; c != "" && since != "-24h" {
		out, err = read("--after-cursor=" + c)
	}
	if err != nil {
		// No place yet, or journald no longer knows it (its files were
		// trimmed): read from the last scan's time.
		out, err = read("--since", since)
	}
	dropJournalCache(env.Sys.FS)
	if err != nil {
		return nil, err
	}
	cursor := state[oomCursorKey]
	if i := bytes.LastIndex(out, []byte(cursorPrefix)); i >= 0 && (i == 0 || out[i-1] == '\n') {
		cursor = strings.TrimSpace(string(out[i+len(cursorPrefix):]))
		out = out[:i]
	}
	// Kills in both readings are counted once.
	seen := map[savedKill]bool{}
	var kills []kill
	var keep []savedKill
	add := func(k kill) {
		s := savedKill{Process: k.process, At: k.at.UTC()}
		if seen[s] || now.Sub(k.at) > time24h {
			return
		}
		seen[s] = true
		keep = append(keep, s)
		kills = append(kills, k)
	}
	for _, s := range saved {
		add(kill{process: s.Process, at: s.At})
	}
	for _, k := range parseKernelLog(out, now) {
		add(k)
	}
	data, _ := json.Marshal(keep)
	err = env.EditState(func(m map[string]string) {
		m[oomAtKey] = now.UTC().Format(time.RFC3339)
		m[oomKillsKey] = string(data)
		if cursor != "" {
			m[oomCursorKey] = cursor
		} else {
			delete(m, oomCursorKey)
		}
	})
	return kills, err
}

// dropJournalCache lets go of the system log's files that journalctl just
// read, so they are not kept in the system's cache on the agent's account
// (see system.RootFS): opening and closing is enough. journald's own pages
// stay; it maps its files, and mapped pages are never dropped.
func dropJournalCache(fsys fs.FS) {
	n := 0
	_ = fs.WalkDir(fsys, "var/log/journal", func(name string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return fs.SkipDir
		case n >= 1000:
			return fs.SkipAll
		}
		if d.Type().IsRegular() && strings.HasSuffix(name, ".journal") {
			n++
			if f, err := fsys.Open(name); err == nil {
				_ = f.Close()
			}
		}
		return nil
	})
}
