package checks

import (
	"context"
	"errors"
	"io/fs"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type diskCheck struct{}

func (diskCheck) ID() string { return "disk" }

func (diskCheck) Run(_ context.Context, env *Env) Result {
	mounts, err := system.DataMounts(env.Sys.FS)
	if errors.Is(err, fs.ErrNotExist) {
		return Skip("not-linux", nil)
	}
	if err != nil {
		return Failed(err)
	}
	lim := env.Cfg.Limits
	var found []Finding
	checked := 0
	for _, m := range mounts {
		u, err := env.Sys.Statfs(m.Point)
		if err != nil || u.TotalBytes == 0 {
			continue
		}
		checked++
		// Like df: used space against the space a normal user can fill.
		used := u.TotalBytes - u.FreeBytes
		space := float64(used) / float64(used+u.AvailBytes) * 100
		vars := map[string]string{"mount": m.Point}
		switch {
		case space > lim.DiskCriticalPercent:
			vars["percent"] = percentText(space)
			found = append(found, Found("space-critical", vars))
		case space > lim.DiskWarningPercent:
			vars["percent"] = percentText(space)
			found = append(found, Found("space-warning", vars))
		}
		if u.TotalInodes > 0 {
			inodes := float64(u.TotalInodes-u.FreeInodes) / float64(u.TotalInodes) * 100
			ivars := map[string]string{"mount": m.Point, "percent": percentText(inodes)}
			switch {
			case inodes > lim.DiskCriticalPercent:
				found = append(found, Found("inodes-critical", ivars))
			case inodes > lim.DiskWarningPercent:
				found = append(found, Found("inodes-warning", ivars))
			}
		}
	}
	if checked == 0 {
		return Failed(errors.New("no disk could be measured"))
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(map[string]string{"limit": percentText(lim.DiskWarningPercent)})
}
