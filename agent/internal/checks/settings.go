package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"time"

	"strings"
)

// Setting is one KEY=value found in an env file or a Compose file. Values
// are kept in memory only while a scan runs, and only the parts the checks
// need (hosts, regions) ever reach a report.
type Setting struct {
	File  string // with the leading slash
	Line  int
	Key   string
	Value string
}

// Settings is everything the data-location checks read from files.
type Settings struct {
	Values  []Setting
	Scripts []Setting // lines from cron jobs and shell scripts, Key empty
	Rclone  []RcloneRemote
	// Blocked is true when a folder could not be read without root.
	Blocked bool
}

// RcloneRemote is one [remote] section of an rclone.conf.
type RcloneRemote struct {
	File, Name, Type, Provider, Region, Endpoint string
}

func (e *Env) Settings() Settings {
	e.settingsOnce.Do(func() { e.settings = readSettings(e) })
	return e.settings
}

func readSettings(e *Env) Settings {
	var s Settings
	fsys := e.Sys.FS
	for _, root := range e.Cfg.Secrets.Paths {
		root = strings.Trim(root, "/")
		_ = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					s.Blocked = true
				}
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] || strings.Count(p, "/")-strings.Count(root, "/") > 5 {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			name := d.Name()
			kind, isSetting := classify(name)
			isScript := strings.HasSuffix(name, ".sh")
			isRclone := name == "rclone.conf"
			if (!isSetting || kind == kindHistory) && !isScript && !isRclone {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > 1<<20 {
				return nil
			}
			data, err := fs.ReadFile(fsys, p)
			if errors.Is(err, fs.ErrPermission) {
				s.Blocked = true
				return nil
			}
			if err != nil {
				return nil
			}
			full := "/" + p
			switch {
			case isRclone:
				s.Rclone = append(s.Rclone, parseRclone(full, data)...)
			case isScript:
				s.Scripts = append(s.Scripts, lines(full, data)...)
			default:
				s.Values = append(s.Values, assignments(full, data)...)
			}
			return nil
		})
	}
	// Running containers' environments: Compose loads env files from
	// anywhere (such as /etc/app/app.env), and the container holds the
	// result. Only the data-location checks read these, for addresses.
	if e.Sys.Docker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cs, err := e.Sys.Docker.Containers(ctx)
		cancel()
		if err == nil {
			for _, c := range cs {
				for i, kv := range c.Env {
					k, v, ok := strings.Cut(kv, "=")
					v = strings.TrimSpace(v)
					if !ok || k == "" || v == "" || strings.HasPrefix(v, "$") {
						continue
					}
					s.Values = append(s.Values, Setting{File: "container " + c.Name, Line: i + 1, Key: strings.ToUpper(k), Value: v})
				}
			}
		}
	}
	for _, cron := range []string{"etc/crontab", "etc/cron.d/*", "var/spool/cron/crontabs/*"} {
		files, _ := fs.Glob(fsys, cron)
		if strings.HasPrefix(cron, "var/spool") {
			if _, err := fs.ReadDir(fsys, "var/spool/cron/crontabs"); errors.Is(err, fs.ErrPermission) {
				s.Blocked = true
			}
		}
		for _, f := range files {
			if data, err := fs.ReadFile(fsys, f); err == nil {
				s.Scripts = append(s.Scripts, lines("/"+f, data)...)
			}
		}
	}
	return s
}

func assignments(file string, data []byte) []Setting {
	var out []Setting
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		m := assignment.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		v := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if v == "" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "#") {
			continue
		}
		out = append(out, Setting{File: file, Line: n, Key: strings.ToUpper(m[1]), Value: v})
	}
	return out
}

func lines(file string, data []byte) []Setting {
	var out []Setting
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		t := strings.TrimSpace(sc.Text())
		if t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, Setting{File: file, Line: n, Value: t})
		}
	}
	return out
}

func parseRclone(file string, data []byte) []RcloneRemote {
	var out []RcloneRemote
	var cur *RcloneRemote
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			out = append(out, RcloneRemote{File: file, Name: strings.Trim(t, "[]")})
			cur = &out[len(out)-1]
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || cur == nil {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "type":
			cur.Type = v
		case "provider":
			cur.Provider = v
		case "region":
			cur.Region = v
		case "endpoint":
			cur.Endpoint = v
		}
	}
	return out
}
