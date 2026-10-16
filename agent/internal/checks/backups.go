package checks

import (
	"context"
	"errors"
	"fmt"
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
	opened := 0
	for _, p := range cfg.Paths {
		newest, err := newestBackup(env.Sys.FS, strings.TrimPrefix(p, "/"))
		switch {
		case errors.Is(err, fs.ErrPermission):
			if !env.Sys.Root {
				return NeedsRoot()
			}
			return Failed(err)
		case errors.Is(err, fs.ErrNotExist) || (err == nil && newest.name == ""):
			found = append(found, Found("empty", map[string]string{"path": p}))
			continue
		case err != nil:
			return Failed(err)
		}
		if newest.at.After(newestAll) {
			newestAll = newest.at
		}
		if age := now.Sub(newest.at); age > maxAge {
			found = append(found, Found("old", map[string]string{
				"path":  p,
				"age":   ageText(age),
				"limit": strconv.Itoa(cfg.MaxAgeHours),
				"when":  newest.at.In(now.Location()).Format("Mon 2 Jan at 15:04"),
			}))
		}
		v, before := checkNewest(env, p, newest)
		file := "/" + newest.name
		switch {
		case !v.ok:
			found = append(found, Found("unreadable", map[string]string{"path": p, "file": file, "reason": v.reason}))
		case before > 0 && newest.size*5 < before && before >= shrinkFloor:
			found = append(found, Found("shrank", map[string]string{
				"path": p, "file": file,
				"size": bytesText(uint64(max(newest.size, 0))), "before": bytesText(uint64(max(before, 0))), // #nosec G115 -- sizes are never negative; max keeps them so
			}))
		case v.checked:
			opened++
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	opens := ""
	if opened == len(cfg.Paths) {
		opens = ", and it opens"
	}
	return Pass(map[string]string{"age": ageText(now.Sub(newestAll)), "opens": opens})
}

// shrinkFloor keeps tiny backups, such as a settings export, from being
// called shrunk over a few bytes.
const shrinkFloor = 1 << 20

type backupFile struct {
	name string // without the leading slash
	at   time.Time
	size int64
}

// newestBackup returns the most recently changed file under dir.
func newestBackup(fsys fs.FS, dir string) (backupFile, error) {
	var newest backupFile
	seen := 0
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if seen++; seen > walkLimit {
			return fs.SkipAll
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil && info.ModTime().After(newest.at) {
				newest = backupFile{name: p, at: info.ModTime(), size: info.Size()}
			}
		}
		return nil
	})
	return newest, err
}

// checkNewest reads the newest backup through once, when it is new, and
// remembers what it found and the size of the one before, so a backup
// that suddenly shrinks is noticed.
func checkNewest(env *Env, dir string, b backupFile) (verdict, int64) {
	key := "backup/" + strings.TrimPrefix(dir, "/")
	print := fmt.Sprintf("%s|%d|%d", b.name, b.size, b.at.Unix())
	var last, before string
	_ = env.EditState(func(m map[string]string) { last, before = m[key], m[key+"/before"] })
	if f, rest, ok := strings.Cut(last, "#"); ok && f == print {
		ok, reason, _ := strings.Cut(rest, "|")
		size, _ := strconv.ParseInt(before, 10, 64)
		return verdict{ok: ok == "ok" || ok == "unchecked", checked: ok == "ok", reason: reason}, size
	}
	v := verifyBackup(env.Sys.FS, b.name, b.size)
	// The size of the backup before this one: the last one seen, if it
	// was a different file or a different write.
	prev := int64(0)
	if f, _, ok := strings.Cut(last, "#"); ok && f != print {
		parts := strings.Split(f, "|")
		if len(parts) == 3 {
			prev, _ = strconv.ParseInt(parts[1], 10, 64)
		}
	} else {
		prev, _ = strconv.ParseInt(before, 10, 64)
	}
	state := "unchecked"
	switch {
	case !v.ok:
		state = "bad"
	case v.checked:
		state = "ok"
	}
	_ = env.EditState(func(m map[string]string) {
		m[key] = print + "#" + state + "|" + v.reason
		if prev > 0 {
			m[key+"/before"] = strconv.FormatInt(prev, 10)
		}
	})
	return v, prev
}
