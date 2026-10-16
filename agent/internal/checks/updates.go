package checks

import (
	"bufio"
	"bytes"
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type updatesCheck struct{}

func (updatesCheck) ID() string { return "updates" }

// statePrefix marks the update dates in the scan's state file.
const statePrefix = "security-update/"

func (updatesCheck) Run(ctx context.Context, env *Env) Result {
	if !env.Sys.Exec.Has("apt-get") {
		return Skip("no-apt", nil)
	}
	// -s simulates: apt prints what it would install and changes nothing.
	out, err := env.Sys.Exec.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
	if err != nil {
		return Failed(err)
	}
	pending := securityUpdates(out)

	// apt does not record when an update appeared, so the scan notes the
	// day it first sees each one.
	now := env.Sys.Now()
	limit := time.Duration(env.Cfg.Limits.UpdateDays) * 24 * time.Hour
	old := 0
	err = env.EditState(func(state map[string]string) {
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
