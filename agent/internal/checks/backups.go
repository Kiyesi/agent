package checks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

type backupsCheck struct{}

func (backupsCheck) ID() string { return "backups" }

// walkLimit stops a walk of a very large folder from slowing the scan.
const walkLimit = 20000

func (backupsCheck) Run(ctx context.Context, env *Env) Result {
	cfg := env.Cfg.Backups
	if len(cfg.Paths) == 0 {
		return noBackupsNamed(ctx, env)
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

// dataDirs are where databases installed on a server keep their data.
var dataDirs = map[string]string{
	"var/lib/postgresql": "PostgreSQL", "var/lib/mysql": "MySQL", "var/lib/mongodb": "MongoDB",
	"var/lib/redis": "Redis", "var/lib/valkey": "Valkey", "var/lib/elasticsearch": "Elasticsearch",
	"var/lib/clickhouse": "ClickHouse",
}

// databaseImages are the words in a container image that runs a database.
var databaseImages = []string{"postgres", "postgis", "timescale", "mysql", "mariadb", "percona", "mongo",
	"redis", "valkey", "keydb", "elasticsearch", "opensearch", "clickhouse", "cassandra", "couchdb", "influxdb", "neo4j"}

// noBackupsNamed decides what no backup folder means, from where this
// server's data lives. Data on this server with no backup named is a
// warning. Data only in hosted databases is backed up there, by its
// provider's plan, which Kiyesi cannot see from here; and a server whose
// apps name no database at all has nothing for this check to look at.
// Neither of those costs points: a warning there was wrong for a server
// whose only database is MongoDB Atlas.
func noBackupsNamed(ctx context.Context, env *Env) Result {
	here := map[string]bool{}
	for dir, name := range dataDirs {
		if fi, err := fs.Stat(env.Sys.FS, dir); err == nil && fi.IsDir() {
			here[name] = true
		}
	}
	if cs, err := env.Containers(ctx); err == nil {
		for _, c := range cs {
			if c.Status != "running" {
				continue
			}
			img := strings.ToLower(c.Image)
			for _, w := range databaseImages {
				if strings.Contains(img, w) {
					here["a "+w+" container ("+c.Name+")"] = true
					break
				}
			}
		}
	}
	var elsewhere []string
	seen := map[string]bool{}
	for _, d := range env.Databases(ctx) {
		if d.local {
			here[d.kind] = true
			continue
		}
		name := d.host
		if d.provider != "" {
			name = d.provider + " (" + d.host + ")"
		}
		if !seen[name] {
			seen[name] = true
			elsewhere = append(elsewhere, name)
		}
	}
	if len(here) > 0 {
		// Backups sent elsewhere (restic, rclone, aws s3 in a timed job)
		// are a backup: Kiyesi only cannot open them from here.
		if places, err := packs.LoadPlaces(); err == nil {
			var to []string
			for _, b := range backups(env, places) {
				to = append(to, b.target)
			}
			if len(to) > 0 {
				sort.Strings(to)
				return Skip("offsite", map[string]string{"to": strings.Join(to, ", ")})
			}
		}
		return Fail(Found("not-set", nil))
	}
	if len(elsewhere) > 0 {
		sort.Strings(elsewhere)
		return Skip("elsewhere", map[string]string{"where": strings.Join(elsewhere, ", ")})
	}
	return Skip("no-data", nil)
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
