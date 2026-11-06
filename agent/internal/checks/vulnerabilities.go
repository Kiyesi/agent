package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/budget"
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
	// The agent close to its memory limit: the scan, the heaviest check,
	// waits for its next turn rather than slow the server.
	if budget.Skip(budget.Vulnerabilities) {
		return Skip("busy", nil)
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
	flaws, err := runTrivy(ctx, env, append(args, "/"))
	if r, stop := trivyProblem(err); stop {
		return r
	}
	if len(flaws) > 0 {
		found = append(found, Found("system", map[string]string{"count": strconv.Itoa(len(flaws)), "flaws": flawWords(flaws)}))
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
		flaws, err := runTrivy(ctx, env, append(args, img))
		if r, stop := trivyProblem(err); stop {
			return r
		}
		if len(flaws) > 0 {
			f := Found("image", map[string]string{"count": strconv.Itoa(len(flaws)), "image": img, "flaws": flawWords(flaws), "name": imageName(img)})
			// An image published by someone else is updated by them, or
			// patched on top; one built here is rebuilt.
			if publishedImage(img) {
				f.Variant = "published"
			}
			found = append(found, f)
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

// kernelPkgRE finds the kernel version a package belongs to, such as
// linux-headers-6.8.0-146-generic: 6.8.0-146.
var kernelPkgRE = regexp.MustCompile(`^linux-(?:headers|image|image-unsigned|modules|modules-extra|tools|cloud-tools|buildinfo)-(\d+\.\d+\.\d+-\d+)`)

// runningKernel is the running kernel's version without its flavour
// (6.8.0-147 for 6.8.0-147-generic), or "" when it cannot be read.
func runningKernel(env *Env) string {
	b, err := fs.ReadFile(env.Sys.FS, "proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)`).FindStringSubmatch(strings.TrimSpace(string(b)))
	if m == nil {
		return ""
	}
	return m[1]
}

// flaw is one critical vulnerability with a fix: the package it is in,
// the version installed and the first version that fixes it.
type flaw struct{ ID, Pkg, Installed, Fixed string }

// flawWords names the flaws, at most three, so the person knows which
// package to upgrade and to what: "brotli-libs 1.2.0-r0 to 1.2.1-r0
// (CVE-2026-111497)".
func flawWords(fs []flaw) string {
	var parts []string
	for i, f := range fs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(fs)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s to %s (%s)", f.Pkg, f.Installed, f.Fixed, f.ID))
	}
	return strings.Join(parts, ", ")
}

// imageName is an image without its digest: what to pull again.
func imageName(img string) string {
	name, _, _ := strings.Cut(img, "@")
	return name
}

// publishedImage tells an image someone else publishes on Docker Hub's
// official list or under a vendor's name (caddy, nginx, postgres,
// bitnami/redis) from one built here (a local name, or one in the team's
// own registry). Docker Hub names have no registry host before the first
// slash; a host has a dot or a port, or is localhost.
func publishedImage(img string) bool {
	name := imageName(img)
	// Tagged local: built on this server, so there is nothing to pull.
	if strings.HasSuffix(name, ":local") {
		return false
	}
	first, _, hasSlash := strings.Cut(name, "/")
	if !hasSlash {
		return true
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return strings.HasPrefix(name, "docker.io/") || strings.HasPrefix(name, "index.docker.io/")
	}
	return true
}

func runTrivy(ctx context.Context, env *Env, args []string) ([]flaw, error) {
	out, err := env.Sys.Exec.Run(ctx, "trivy", args...)
	if err != nil {
		return nil, err
	}
	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, errors.New("trivy's answer was not the expected JSON")
	}
	// An old kernel left installed after an update is not running, and
	// sudo apt-get autoremove removes it: it is not counted.
	running := runningKernel(env)
	seen := map[string]bool{}
	var out2 []flaw
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			if m := kernelPkgRE.FindStringSubmatch(v.PkgName); m != nil && running != "" && m[1] != running {
				continue
			}
			if v.FixedVersion != "" && !seen[v.VulnerabilityID] {
				seen[v.VulnerabilityID] = true
				out2 = append(out2, flaw{ID: v.VulnerabilityID, Pkg: v.PkgName, Installed: v.InstalledVersion, Fixed: v.FixedVersion})
			}
		}
	}
	return out2, nil
}
