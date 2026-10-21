package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type secretsCheck struct{}

func (secretsCheck) ID() string { return "secrets-in-files" }

type fileKind int

const (
	kindEnv fileKind = iota
	kindCompose
	kindHistory
)

// skipDirs are never searched: they hold code or packages, not settings.
var skipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, ".cache": true, "__pycache__": true, ".npm": true, ".venv": true}

var historyNames = map[string]bool{
	".bash_history": true, ".zsh_history": true, ".history": true, ".sh_history": true,
	".mysql_history": true, ".psql_history": true, ".rediscli_history": true, ".mongosh_history": true,
}

func classify(name string) (fileKind, bool) {
	lower := strings.ToLower(name)
	switch {
	case historyNames[lower]:
		return kindHistory, true
	case lower == ".env" || strings.HasSuffix(lower, ".env") ||
		(strings.HasPrefix(lower, ".env.") && !strings.HasSuffix(lower, ".example") && !strings.HasSuffix(lower, ".sample") && !strings.HasSuffix(lower, ".template") && !strings.HasSuffix(lower, ".dist")):
		return kindEnv, true
	case (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose")) &&
		(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return kindCompose, true
	}
	return 0, false
}

// secretKey matches setting names that usually hold a secret.
var secretKey = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|DSN|DATABASE_URL|MONGO(DB)?_URI|REDIS_URL|AUTH_KEY)`)

// assignment matches KEY=value, KEY: value and "- KEY=value" lines.
var assignment = regexp.MustCompile(`^\s*(?:-\s*)?(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*(.*)$`)

// builtinRules is the small rule set used when gitleaks is not installed.
// Each matches a secret's shape; the value itself is never kept.
var builtinRules = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                  // AWS access key
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{40,}`),     // GitHub token
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                      // Slack token
	regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}`), // Stripe live key
	regexp.MustCompile(`sk_live_[a-f0-9]{30,}`),                             // Paystack live key
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{3,}@`), // password in a URL
	regexp.MustCompile(`(?i)\bmysql\b.*\s-p\S{3,}`),                  // mysql -pPASSWORD
	regexp.MustCompile(`(?i)\bcurl\b.*\s-u\s*\S+:\S{3,}`),            // curl -u user:password
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*["']?[^\s"'$]{6,}`),
}

func (secretsCheck) Run(ctx context.Context, env *Env) Result {
	fsys := env.Sys.FS
	useGitleaks := env.Sys.Exec.Has("gitleaks")
	blocked := false
	checked := 0
	var found []Finding

	for _, root := range env.Cfg.Secrets.Paths {
		root = strings.Trim(root, "/")
		err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					blocked = true
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
			kind, ok := classify(d.Name())
			if !ok || !d.Type().IsRegular() {
				return nil
			}
			if checked++; checked > walkLimit {
				return fs.SkipAll
			}
			info, err := d.Info()
			if err != nil || info.Size() > 1<<20 {
				return nil
			}
			data, err := readUserFile(fsys, p)
			if errors.Is(err, fs.ErrPermission) {
				blocked = true
				return nil
			}
			if err != nil {
				return nil
			}
			full := "/" + p
			var lines []int
			switch kind {
			case kindHistory:
				lines = secretLines(ctx, env, useGitleaks, full, data, false)
			default:
				lines = secretLines(ctx, env, useGitleaks, full, data, true)
			}
			if len(lines) == 0 {
				return nil
			}
			switch {
			case kind == kindCompose:
				found = append(found, Found("in-compose", map[string]string{"path": full, "line": strconv.Itoa(lines[0])}))
			case kind == kindHistory:
				found = append(found, Found("in-history", map[string]string{"path": full, "line": strconv.Itoa(lines[0])}))
			case info.Mode().Perm()&0o004 != 0:
				found = append(found, Found("world-readable", map[string]string{"path": full}))
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			if errors.Is(err, fs.ErrPermission) {
				blocked = true
				continue
			}
			return Failed(err)
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Vars["path"] < found[j].Vars["path"] })
	if len(found) > 0 {
		return Fail(found...)
	}
	if blocked && !env.Sys.Root {
		return NeedsRoot()
	}
	return Pass(map[string]string{"count": strconv.Itoa(checked)})
}

// secretLines returns the line numbers that hold a secret, never the
// secrets. In settings files, a line counts when a secret-sounding name has
// a literal value; ${VAR} references are not secrets.
func secretLines(ctx context.Context, env *Env, useGitleaks bool, full string, data []byte, settings bool) []int {
	var lines []int
	if settings {
		sc := bufio.NewScanner(bytes.NewReader(data))
		n := 0
		for sc.Scan() {
			n++
			m := assignment.FindStringSubmatch(sc.Text())
			if m == nil || !secretKey.MatchString(m[1]) {
				continue
			}
			v := strings.Trim(strings.TrimSpace(m[2]), `"'`)
			if v == "" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "#") || v == "changeme" || strings.EqualFold(v, "null") || v == "~" {
				continue
			}
			lines = append(lines, n)
		}
		if len(lines) > 0 {
			return lines
		}
	}
	if useGitleaks {
		return gitleaksLines(ctx, env, full)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		for _, r := range builtinRules {
			if r.Match(sc.Bytes()) {
				lines = append(lines, n)
				break
			}
		}
	}
	return lines
}

// gitleaksLines runs gitleaks on one file with its output redacted, and
// keeps only the line numbers.
func gitleaksLines(ctx context.Context, env *Env, full string) []int {
	out, err := env.Sys.Exec.Run(ctx, "gitleaks", "dir", full, "--no-banner", "--redact", "--exit-code", "0",
		"--report-format", "json", "--report-path", "-", "--log-level", "error")
	if err != nil {
		return nil
	}
	var hits []struct {
		StartLine int `json:"StartLine"`
	}
	if json.Unmarshal(out, &hits) != nil {
		return nil
	}
	lines := make([]int, 0, len(hits))
	for _, h := range hits {
		lines = append(lines, h.StartLine)
	}
	sort.Ints(lines)
	return lines
}
