package checks

import (
	"context"
	"errors"
	"strconv"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type containersCheck struct{}

func (containersCheck) ID() string { return "containers" }

func (containersCheck) Run(ctx context.Context, env *Env) Result {
	cs, err := env.Containers(ctx)
	if errors.Is(err, system.ErrNeedsRoot) {
		return NeedsRoot()
	}
	if err != nil {
		return Failed(err)
	}
	if len(cs) == 0 {
		return PassNone()
	}
	now := env.Sys.Now()
	dies, err := env.Sys.Docker.Dies(ctx, now.Add(-time1h), now)
	if err != nil {
		return Failed(err)
	}
	var found []Finding
	running := 0
	for _, c := range cs {
		name := map[string]string{"name": c.Name}
		switch c.Status {
		case "running":
			running++
		case "exited", "dead":
			// A container that finished cleanly with no restart policy is a
			// one-off job, such as a migration.
			if c.ExitCode != 0 || (c.RestartPolicy != "" && c.RestartPolicy != "no") {
				found = append(found, Found("exited", map[string]string{"name": c.Name, "code": strconv.Itoa(c.ExitCode)}))
			}
			continue
		}
		if c.Health == "unhealthy" {
			found = append(found, Found("unhealthy", name))
		}
		if n := dies[c.ID]; n >= env.Cfg.Limits.RestartsPerHour {
			found = append(found, Found("restarts", map[string]string{"name": c.Name, "count": strconv.Itoa(n)}))
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(map[string]string{"count": strconv.Itoa(running)})
}
