package checks

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type vulnerabilitiesCheck struct{}

func (vulnerabilitiesCheck) ID() string { return "vulnerabilities" }

var trivyVersionRE = regexp.MustCompile(`Version:\s*v?(\d+)\.(\d+)\.(\d+)`)

// compromisedTrivy reports the releases taken over in March 2026 (CVE-2026-33634).
func compromisedTrivy(major, minor, patch int) bool {
	return major == 0 && minor == 69 && patch >= 4 && patch <= 6
}

// trivyArgs never update the database: a scan downloads nothing.
var trivyArgs = []string{
	"--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-check-update",
	"--scanners", "vuln", "--severity", "CRITICAL", "--ignore-unfixed",
	"--format", "json", "--quiet",
}

// trivyCache is where the server's own Trivy database lives, refreshed by
// a separate nightly job so a scan never downloads it.
const trivyCache = "/var/lib/kiyesi/trivy"

func (c vulnerabilitiesCheck) Run(ctx context.Context, env *Env) Result {
	if r, ok := env.remembered(c.ID()); ok {
		return r
	}
	r := c.run(ctx, env)
	env.remember(c.ID(), r)
	return r
}

func (vulnerabilitiesCheck) run(ctx context.Context, env *Env) Result {
	if !env.Sys.Exec.Has("trivy") {
		return Skip("not-installed", nil)
	}
	out, err := env.Sys.Exec.Run(ctx, "trivy", "--version")
	if err != nil {
		return Skip("failed", map[string]string{"reason": err.Error()})
	}
	m := trivyVersionRE.FindStringSubmatch(string(out))
	if m == nil {
		return Skip("failed", map[string]string{"reason": "could not read the Trivy version"})
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	if compromisedTrivy(major, minor, patch) {
		return Skip("bad-version", map[string]string{"version": m[1] + "." + m[2] + "." + m[3]})
	}

	common := trivyArgs
	if _, err := fs.Stat(env.Sys.FS, strings.TrimPrefix(trivyCache, "/")+"/db/trivy.db"); err == nil {
		common = append([]string{"--cache-dir", trivyCache}, trivyArgs...)
	}
	var found []Finding
	args := append([]string{"rootfs", "--pkg-types", "os"}, common...)
	n, err := runTrivy(ctx, env, append(args, "/"))
	if r, stop := trivyProblem(err); stop {
		return r
	}
	if n > 0 {
		found = append(found, Found("system", map[string]string{"count": strconv.Itoa(n)}))
	}

	cs, err := env.Containers(ctx)
	if errors.Is(err, system.ErrNeedsRoot) && len(found) == 0 {
		return NeedsRoot()
	}
	images := map[string]bool{}
	for _, c := range cs {
		if c.Status == "running" {
			images[c.Image] = true
		}
	}
	names := make([]string, 0, len(images))
	for img := range images {
		names = append(names, img)
	}
	sort.Strings(names)
	for _, img := range names {
		args := append([]string{"image"}, common...)
		n, err := runTrivy(ctx, env, append(args, img))
		if r, stop := trivyProblem(err); stop {
			return r
		}
		if n > 0 {
			found = append(found, Found("image", map[string]string{"count": strconv.Itoa(n), "image": img}))
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(nil)
}

// trivyProblem turns Trivy's errors into skips. A missing database is its
// own reason, because the fix is to download it once, outside a scan.
func trivyProblem(err error) (Result, bool) {
	if err == nil {
		return Result{}, false
	}
	msg := err.Error()
	if strings.Contains(msg, "--skip-db-update cannot be specified on the first run") ||
		strings.Contains(msg, "first run cannot skip downloading DB") ||
		strings.Contains(msg, "no such file or directory") && strings.Contains(msg, "trivy.db") {
		return Skip("no-database", nil), true
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return Skip("failed", map[string]string{"reason": msg}), true
}

func runTrivy(ctx context.Context, env *Env, args []string) (int, error) {
	out, err := env.Sys.Exec.Run(ctx, "trivy", args...)
	if err != nil {
		return 0, err
	}
	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				FixedVersion    string `json:"FixedVersion"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return 0, errors.New("trivy's answer was not the expected JSON")
	}
	seen := map[string]bool{}
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			if v.FixedVersion != "" {
				seen[v.VulnerabilityID] = true
			}
		}
	}
	return len(seen), nil
}
