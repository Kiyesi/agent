package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"
)

type memoryCheck struct{}

func (memoryCheck) ID() string { return "memory" }

// MemInfo holds the /proc/meminfo values the checks use, in bytes.
type MemInfo struct {
	Total, Available, SwapTotal uint64
}

func readMemInfo(fsys fs.FS) (MemInfo, error) {
	data, err := fs.ReadFile(fsys, "proc/meminfo")
	if err != nil {
		return MemInfo{}, err
	}
	var m MemInfo
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.Total = kb * 1024
		case "MemAvailable:":
			m.Available = kb * 1024
		case "SwapTotal:":
			m.SwapTotal = kb * 1024
		}
	}
	if m.Total == 0 {
		return m, errors.New("/proc/meminfo has no MemTotal")
	}
	return m, nil
}

func (memoryCheck) Run(_ context.Context, env *Env) Result {
	m, err := readMemInfo(env.Sys.FS)
	if errors.Is(err, fs.ErrNotExist) {
		return Skip("not-linux", nil)
	}
	if err != nil {
		return Failed(err)
	}
	used := float64(m.Total-min(m.Available, m.Total)) / float64(m.Total) * 100
	vars := map[string]string{
		"percent": percentText(used),
		"limit":   percentText(env.Cfg.Limits.MemoryPercent),
		"total":   bytesText(m.Total),
	}
	var found []Finding
	if used > env.Cfg.Limits.MemoryPercent {
		found = append(found, Found("high", vars))
	}
	if m.SwapTotal == 0 && float64(m.Total) < env.Cfg.Limits.SwapBelowMemoryGB*(1<<30) {
		found = append(found, Found("no-swap", vars))
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(vars)
}
