package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type riskyContainersCheck struct{}

func (riskyContainersCheck) ID() string { return "risky-containers" }

func (riskyContainersCheck) Run(ctx context.Context, env *Env) Result {
	cs, err := env.Containers(ctx)
	if errors.Is(err, system.ErrNeedsRoot) {
		return NeedsRoot()
	}
	if err != nil {
		return Failed(err)
	}
	var found []Finding
	running := 0
	for _, c := range cs {
		if c.Status != "running" && c.Status != "restarting" {
			continue
		}
		running++
		vars := map[string]string{"name": c.Name}
		if c.Privileged {
			found = append(found, Found("privileged", vars))
		}
		for _, m := range c.Mounts {
			if m == "/var/run/docker.sock" || m == "/run/docker.sock" {
				found = append(found, Found("docker-socket", vars))
				break
			}
		}
		if runsAsRoot(env, c) {
			found = append(found, Found("root", vars))
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	if running == 0 {
		return PassNone()
	}
	return Pass(nil)
}

// runsAsRoot reads the user the container's main process really runs as.
// Many images (Valkey, Redis, PostgreSQL) start as root and then switch to
// their own user, so the configured user alone would be a false alarm. When
// the process cannot be read, the configured user decides.
func runsAsRoot(env *Env, c system.Container) bool {
	if c.Pid > 0 {
		if data, err := fs.ReadFile(env.Sys.FS, "proc/"+strconv.Itoa(c.Pid)+"/status"); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(data))
			for sc.Scan() {
				if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
					f := strings.Fields(rest)
					// Real, effective, saved and file-system ids: root if the effective id is 0.
					return len(f) > 1 && f[1] == "0"
				}
			}
		}
	}
	switch c.User {
	case "", "root", "0", "0:0", "root:root":
		return true
	}
	return false
}
