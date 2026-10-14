package checks

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

type backupsCheck struct{}

func (backupsCheck) ID() string { return "backups" }

// walkLimit stops a walk of a very large folder from slowing the scan.
const walkLimit = 20000

func (backupsCheck) Run(_ context.Context, env *Env) Result {
	cfg := env.Cfg.Backups
	if len(cfg.Paths) == 0 {
		return Fail(Found("not-set", nil))
	}
	now := env.Sys.Now()
	maxAge := time.Duration(cfg.MaxAgeHours) * time.Hour
	var found []Finding
	var newestAll time.Time
	for _, p := range cfg.Paths {
		newest, err := newestFile(env.Sys.FS, strings.TrimPrefix(p, "/"))
		switch {
		case errors.Is(err, fs.ErrPermission):
			if !env.Sys.Root {
				return NeedsRoot()
			}
			return Failed(err)
		case errors.Is(err, fs.ErrNotExist) || (err == nil && newest.IsZero()):
			found = append(found, Found("empty", map[string]string{"path": p}))
			continue
		case err != nil:
			return Failed(err)
		}
		if newest.After(newestAll) {
			newestAll = newest
		}
		if age := now.Sub(newest); age > maxAge {
			found = append(found, Found("old", map[string]string{
				"path":  p,
				"age":   ageText(age),
				"limit": strconv.Itoa(cfg.MaxAgeHours),
				"when":  newest.In(now.Location()).Format("Mon 2 Jan at 15:04"),
			}))
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(map[string]string{"age": ageText(now.Sub(newestAll))})
}

// newestFile returns the latest change time of any file under dir.
func newestFile(fsys fs.FS, dir string) (time.Time, error) {
	var newest time.Time
	seen := 0
	err := fs.WalkDir(fsys, dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if seen++; seen > walkLimit {
			return fs.SkipAll
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		return nil
	})
	return newest, err
}
