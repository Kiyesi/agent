package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// leftoversCheck finds what was useful while building and has no place on
// a live server: debug switches, development tools, Git folders in the web
// root, logs nothing rotates, and Docker images and cache nothing uses.
type leftoversCheck struct{}

func (leftoversCheck) ID() string { return "leftovers" }

// Thresholds: below these, the space is not worth a line in the report.
// Variables only so the tests can use small files.
var (
	bigLogBytes      int64 = 1 << 30
	dockerWasteBytes int64 = 2 << 30
)

// debugSettings are settings that turn on debug or development mode, with
// the values that do. A setting's value is compared without case.
var debugSettings = map[string][]string{
	"APP_DEBUG":              {"true", "1", "yes", "on"},
	"DEBUG":                  {"true", "1", "yes", "on"},
	"FLASK_DEBUG":            {"true", "1"},
	"DJANGO_DEBUG":           {"true", "1"},
	"NODE_ENV":               {"development", "dev"},
	"APP_ENV":                {"local", "development", "dev"},
	"RAILS_ENV":              {"development"},
	"RACK_ENV":               {"development"},
	"ASPNETCORE_ENVIRONMENT": {"development"},
	"DOTNET_ENVIRONMENT":     {"development"},
	"GIN_MODE":               {"debug"},
	"SPRING_PROFILES_ACTIVE": {"dev", "development", "local"},
	"QUARKUS_PROFILE":        {"dev"},
	"MICRONAUT_ENVIRONMENTS": {"dev", "development", "local"},
	"MIX_ENV":                {"dev"},
	"SYMFONY_ENV":            {"dev"},
}

// listSettings hold several values, such as SPRING_PROFILES_ACTIVE=prod,dev:
// one development value among them is enough.
var listSettings = map[string]bool{"SPRING_PROFILES_ACTIVE": true, "MICRONAUT_ENVIRONMENTS": true}

// debugSetting returns "NAME=value" when one line of an env file or a
// container's environment turns debug on.
func debugSetting(line string) (string, bool) {
	m := assignment.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	v := strings.ToLower(strings.Trim(strings.TrimSpace(m[2]), `"'`))
	values := []string{v}
	if listSettings[m[1]] {
		values = strings.Split(v, ",")
	}
	for _, x := range values {
		for _, bad := range debugSettings[m[1]] {
			if strings.TrimSpace(x) == bad {
				return m[1] + "=" + v, true
			}
		}
	}
	return "", false
}

// wpDebug matches WordPress's define('WP_DEBUG', true).
var wpDebug = regexp.MustCompile(`(?i)define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)`)

// devTools are images made for a developer's machine, by a part of the
// image's name, with the name people know them by.
var devTools = []struct{ part, name string }{
	{"phpmyadmin", "phpMyAdmin"},
	{"adminer", "Adminer"},
	{"mailhog", "MailHog"},
	{"mailpit", "Mailpit"},
	{"maildev", "MailDev"},
	{"pgadmin", "pgAdmin"},
	{"mongo-express", "mongo-express"},
	{"redis-commander", "Redis Commander"},
	{"redisinsight", "RedisInsight"},
}

func devToolOf(image string) (string, bool) {
	// The name without its registry and tag: "dpage/pgadmin4:8" -> "dpage/pgadmin4".
	name := strings.ToLower(image)
	if i := strings.LastIndex(name, "@"); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	for _, t := range devTools {
		if strings.Contains(path.Base(name), t.part) {
			return t.name, true
		}
	}
	return "", false
}

// webRoots are the folders web servers serve from by default.
var webRoots = []string{"var/www", "usr/share/nginx/html", "srv/www", "srv/http"}

// devFile is an env file meant for a developer's machine, whose debug
// settings are expected.
func devFile(name string) bool {
	n := strings.ToLower(name)
	for _, w := range []string{"development", ".dev", "local", "test", "example", "sample", "template", "dist"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

func (leftoversCheck) Run(ctx context.Context, env *Env) Result {
	fsys := env.Sys.FS
	blocked := false
	var found []Finding
	add := func(key string, vars map[string]string) { found = append(found, Found(key, vars)) }
	note := func(err error) bool {
		if errors.Is(err, fs.ErrPermission) {
			blocked = true
		}
		return err != nil
	}

	// Debug switches in env files and wp-config.php.
	seen := map[string]bool{}
	checked := 0
	for _, root := range append(append([]string{}, env.Cfg.Secrets.Paths...), webRoots...) {
		root = strings.Trim(root, "/")
		_ = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if note(err) {
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
			if seen[p] || !d.Type().IsRegular() {
				return nil
			}
			kind, isEnv := classify(d.Name())
			wp := d.Name() == "wp-config.php"
			if (!isEnv || kind != kindEnv || devFile(d.Name())) && !wp {
				return nil
			}
			seen[p] = true
			if checked++; checked > walkLimit {
				return fs.SkipAll
			}
			if info, err := d.Info(); err != nil || info.Size() > 1<<20 {
				return nil
			}
			data, err := fs.ReadFile(fsys, p)
			if note(err) {
				return nil
			}
			if wp {
				if wpDebug.Match(data) {
					add("debug", map[string]string{"path": "/" + p, "setting": "WP_DEBUG=true"})
				}
				return nil
			}
			sc := bufio.NewScanner(bytes.NewReader(data))
			for sc.Scan() {
				if s, ok := debugSetting(sc.Text()); ok {
					add("debug", map[string]string{"path": "/" + p, "setting": s})
					break
				}
			}
			return nil
		})
	}

	// Development tools and debug settings in running containers.
	cs, err := env.Containers(ctx)
	if errors.Is(err, system.ErrNeedsRoot) {
		blocked = true
	}
	for _, c := range cs {
		if c.Status != "running" && c.Status != "restarting" {
			continue
		}
		if tool, ok := devToolOf(c.Image); ok {
			key := "dev-tool"
			for _, p := range c.Ports {
				if !loopback(p.HostIP) {
					key = "dev-tool-public"
					break
				}
			}
			add(key, map[string]string{"name": c.Name, "tool": tool})
		}
		for _, e := range c.Env {
			if s, ok := debugSetting(e); ok {
				add("debug-container", map[string]string{"name": c.Name, "setting": s})
				break
			}
		}
	}

	// Git folders in a web root: the whole code and its history.
	for _, root := range webRoots {
		_ = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if note(err) {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if d.Name() == ".git" {
				if _, err := fs.Stat(fsys, p+"/HEAD"); err == nil {
					add("git-folder", map[string]string{"path": "/" + p})
				}
				return fs.SkipDir
			}
			if d.Name() == "node_modules" || d.Name() == "vendor" || strings.Count(p, "/")-strings.Count(root, "/") > 3 {
				return fs.SkipDir
			}
			return nil
		})
	}

	// Logs that grew past 1 GB: on their own, and containers' with no size limit.
	_ = fs.WalkDir(fsys, "var/log", func(p string, d fs.DirEntry, err error) error {
		if note(err) {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if strings.Count(p, "/") > 3 || d.Name() == "journal" {
				return fs.SkipDir
			}
			return nil
		}
		if info, err := d.Info(); err == nil && d.Type().IsRegular() && info.Size() >= bigLogBytes {
			add("big-log", map[string]string{"path": "/" + p, "size": bytesText(uint64(info.Size()))})
		}
		return nil
	})
	for _, c := range cs {
		if (c.LogDriver != "" && c.LogDriver != "json-file") || c.LogMaxSize != "" {
			continue
		}
		info, err := fs.Stat(fsys, "var/lib/docker/containers/"+c.ID+"/"+c.ID+"-json.log")
		if note(err) {
			continue
		}
		if info.Size() >= bigLogBytes {
			add("big-container-log", map[string]string{"name": c.Name, "size": bytesText(uint64(info.Size()))})
		}
	}

	// Docker's images and build cache nothing uses.
	if env.Sys.Docker != nil {
		u, err := env.Sys.Docker.DiskUsage(ctx)
		if errors.Is(err, system.ErrNeedsRoot) {
			blocked = true
		} else if err == nil && u.Reclaimable() >= dockerWasteBytes {
			add("docker-waste", map[string]string{"size": bytesText(uint64(u.Reclaimable()))})
		}
	}

	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Vars["path"] != b.Vars["path"] {
			return a.Vars["path"] < b.Vars["path"]
		}
		return a.Vars["name"] < b.Vars["name"]
	})
	if len(found) > 0 {
		return Fail(found...)
	}
	if blocked && !env.Sys.Root {
		return NeedsRoot()
	}
	return Pass(nil)
}

// loopback is a published port reachable only from the server itself.
func loopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}
