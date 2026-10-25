package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"regexp"
	"sort"
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
	case env.Sys.Root && env.Sys.Exec.Has("journalctl"):
		out, err := env.Sys.Exec.Run(ctx, "journalctl", "-k", "--since", "-24h", "--no-pager", "-q", "-o", "short-iso")
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
