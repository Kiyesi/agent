package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"strconv"
	"strings"
)

// loadCheck stands in for CPU in a one-off scan: it reads the 15-minute
// load average per core.
type loadCheck struct{}

func (loadCheck) ID() string { return "load" }

func (loadCheck) Run(_ context.Context, env *Env) Result {
	data, err := fs.ReadFile(env.Sys.FS, "proc/loadavg")
	if errors.Is(err, fs.ErrNotExist) {
		return Skip("not-linux", nil)
	}
	if err != nil {
		return Failed(err)
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return Failed(errors.New("/proc/loadavg is not in the expected form"))
	}
	load15, err := strconv.ParseFloat(f[2], 64)
	if err != nil {
		return Failed(err)
	}
	cores := countCores(env.Sys.FS)
	per := load15 / float64(cores)
	vars := map[string]string{
		"load":  fmt.Sprintf("%.2f", per),
		"limit": strconv.FormatFloat(env.Cfg.Limits.LoadPerCore, 'f', -1, 64),
	}
	if per > env.Cfg.Limits.LoadPerCore {
		return Fail(Found("high", vars))
	}
	return Pass(vars)
}

func countCores(fsys fs.FS) int {
	data, err := fs.ReadFile(fsys, "proc/cpuinfo")
	if err == nil {
		n := bytes.Count(data, []byte("\nprocessor\t"))
		if bytes.HasPrefix(data, []byte("processor\t")) {
			n++
		}
		if n > 0 {
			return n
		}
	}
	return runtime.NumCPU()
}
