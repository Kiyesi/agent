package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type oomCheck struct{}

func (oomCheck) ID() string { return "oom" }

// The kernel's lines for a kill, and for one made by the kiyesi service's
// own memory limit, shared with the agent's kill watch.
var (
	killedRE   = system.KilledRE
	ownLimitRE = system.OwnLimitRE
)

type kill struct {
	process string
	at      time.Time
}

func (oomCheck) Run(ctx context.Context, env *Env) Result {
	now := env.Sys.Now()
	var kills []kill
	switch {
	case env.Kills != nil && env.Sys.Exec.Has("journalctl"):
		// The background agent: kills recorded as they happened, from the
		// system log's follower. A search of the log for kernel lines reads
		// the whole journal, gigabytes on a busy server, so it never runs
		// here; a scan by hand still does.
		forgetOldPlace(env)
		since, recorded, err := env.Kills.Load(now)
		if err != nil {
			return Failed(err)
		}
		if since.IsZero() {
			return Skip("starting", nil)
		}
		for _, k := range recorded {
			kills = append(kills, kill{process: k.Process, at: k.At})
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

// forgetOldPlace removes what 0.48.4 kept to read the log in parts.
func forgetOldPlace(env *Env) {
	if env.Sys.State == nil {
		return
	}
	if m, err := env.Sys.State.Load(); err != nil || m["oom/at"] == "" && m["oom/cursor"] == "" && m["oom/kills"] == "" {
		return
	}
	_ = env.EditState(func(m map[string]string) {
		delete(m, "oom/at")
		delete(m, "oom/cursor")
		delete(m, "oom/kills")
	})
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
