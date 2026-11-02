package checks

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

const trivyRootfs = "trivy rootfs --pkg-types os --skip-db-update --skip-java-db-update --offline-scan --skip-check-update --scanners vuln --severity CRITICAL --ignore-unfixed --format json --quiet /"

func TestVulnerabilitiesWithoutTrivyIsSkipped(t *testing.T) {
	if r := run(t, vulnerabilitiesCheck{}, newTestEnv()); r.SkipKey != "not-installed" {
		t.Errorf("want not-installed, got %+v", r)
	}
}

func TestVulnerabilitiesRefusesCompromisedTrivy(t *testing.T) {
	for _, v := range []string{"0.69.4", "0.69.5", "0.69.6"} {
		e := newTestEnv().command("trivy --version", "Version: "+v+"\n")
		r := run(t, vulnerabilitiesCheck{}, e)
		if r.SkipKey != "bad-version" || r.SkipVars["version"] != v {
			t.Errorf("%s: want bad-version, got %+v", v, r)
		}
		for _, ran := range e.runner.ran {
			if ran != "trivy --version" {
				t.Errorf("%s: ran %q after refusing the version", v, ran)
			}
		}
	}
}

func TestVulnerabilitiesNeverDownloads(t *testing.T) {
	e := newTestEnv().command("trivy --version", "Version: 0.74.0\n").command(trivyRootfs, mustRead(t, "trivy-rootfs.json"))
	e.docker = fakeDocker{cs: []system.Container{{Name: "api", Image: "checkout-api:3.8.1", Status: "running"}}}
	e.runner.outs["trivy image --skip-db-update --skip-java-db-update --offline-scan --skip-check-update --scanners vuln --severity CRITICAL --ignore-unfixed --format json --quiet checkout-api:3.8.1"] = `{"Results":[]}`
	r := run(t, vulnerabilitiesCheck{}, e)
	wantStatus(t, r, StatusFail, "system")
	if r.Findings[0].Vars["count"] != "1" {
		t.Errorf("the same CVE in two packages counts once: %v", r.Findings[0].Vars)
	}
	for _, ran := range e.runner.ran {
		if ran != "trivy --version" && !contains(ran, "--skip-db-update") {
			t.Errorf("ran Trivy without --skip-db-update: %q", ran)
		}
	}
}

func TestVulnerabilitiesLeaveOutOldKernelsThatAreNotRunning(t *testing.T) {
	report := `{"Results":[{"Vulnerabilities":[
		{"VulnerabilityID":"CVE-1","PkgName":"linux-headers-6.8.0-146-generic","FixedVersion":"6.8.0-147.147"},
		{"VulnerabilityID":"CVE-2","PkgName":"linux-modules-6.8.0-142-generic","FixedVersion":"6.8.0-147.147"},
		{"VulnerabilityID":"CVE-3","PkgName":"linux-image-6.8.0-147-generic","FixedVersion":"6.8.0-148.148"},
		{"VulnerabilityID":"CVE-4","PkgName":"openssl","FixedVersion":"3.0.13-0ubuntu3.6"}
	]}]}`
	e := newTestEnv().command("trivy --version", "Version: 0.74.0\n").command(trivyRootfs, report)
	e.fs["proc/sys/kernel/osrelease"] = &fstest.MapFile{Data: []byte("6.8.0-147-generic\n")}
	r := run(t, vulnerabilitiesCheck{}, e)
	wantStatus(t, r, StatusFail, "system")
	// Old kernels 146 and 142 are not running: only the running kernel and openssl count.
	if r.Findings[0].Vars["count"] != "2" {
		t.Errorf("count = %v", r.Findings[0].Vars)
	}
}

func TestVulnerabilitiesWithoutDatabaseIsSkipped(t *testing.T) {
	e := newTestEnv().command("trivy --version", "Version: 0.74.0\n")
	e.runner.errs[trivyRootfs] = &system.CommandError{Name: "trivy", Code: 1, Stderr: "FATAL init error: --skip-db-update cannot be specified on the first run"}
	if r := run(t, vulnerabilitiesCheck{}, e); r.SkipKey != "no-database" {
		t.Errorf("want no-database, got %+v", r)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestVulnerabilitiesUsesTheServersOwnDatabase(t *testing.T) {
	e := newTestEnv().command("trivy --version", "Version: 0.74.0\n").file("var/lib/kiyesi/trivy/db/trivy.db", "x")
	e.runner.outs["trivy rootfs --pkg-types os --cache-dir /var/lib/kiyesi/trivy *"] = `{"Results":[]}`
	wantStatus(t, run(t, vulnerabilitiesCheck{}, e), StatusPass)
	if !contains(e.runner.ran[1], "--cache-dir /var/lib/kiyesi/trivy") {
		t.Errorf("ran %q", e.runner.ran[1])
	}
}

func TestTheAgentReusesAVulnerabilityResult(t *testing.T) {
	e := newTestEnv().command("trivy --version", "Version: 0.74.0\n").command(trivyRootfs, mustRead(t, "trivy-rootfs.json"))
	env := e.env()
	env.ReuseSlowFor = 6 * time.Hour
	first := vulnerabilitiesCheck{}.Run(context.Background(), env)
	ran := len(e.runner.ran)
	second := vulnerabilitiesCheck{}.Run(context.Background(), env)
	if len(e.runner.ran) != ran {
		t.Errorf("Trivy ran again within 6 hours: %v", e.runner.ran[ran:])
	}
	if second.Status != first.Status || len(second.Findings) != len(first.Findings) {
		t.Errorf("reused %+v, want %+v", second, first)
	}
	// A scan run by hand checks fresh.
	byHand := e.env()
	_ = vulnerabilitiesCheck{}.Run(context.Background(), byHand)
	if len(e.runner.ran) == ran {
		t.Error("a scan by hand reused an old result")
	}
}

// Each flaw is named with its package, the version installed and the one
// that fixes it, so the person knows what to upgrade; an image published by
// someone else is told to be pulled again or patched on top, one built here
// to be rebuilt.
func TestVulnerabilitiesNameEachFlawAndWhoUpdatesTheImage(t *testing.T) {
	caddy := "caddy:2.11.7-alpine@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5"
	own := "ghcr.io/acme/checkout-api:3.8.1"
	flaws := `{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-111497","PkgName":"brotli-libs","InstalledVersion":"1.2.0-r0","FixedVersion":"1.2.1-r0"}]}]}`
	image := "trivy image --skip-db-update --skip-java-db-update --offline-scan --skip-check-update --scanners vuln --severity CRITICAL --ignore-unfixed --format json --quiet "
	e := newTestEnv().command("trivy --version", "Version: 0.74.0\n").command(trivyRootfs, `{"Results":[]}`)
	e.docker = fakeDocker{cs: []system.Container{{Name: "caddy", Image: caddy, Status: "running"}, {Name: "api", Image: own, Status: "running"}}}
	e.runner.outs[image+caddy] = flaws
	e.runner.outs[image+own] = flaws
	r := run(t, vulnerabilitiesCheck{}, e)
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.Vars["flaws"] != "brotli-libs 1.2.0-r0 to 1.2.1-r0 (CVE-2026-111497)" {
			t.Errorf("flaws = %q", f.Vars["flaws"])
		}
		switch f.Vars["image"] {
		case caddy:
			if f.Variant != "published" || f.Vars["name"] != "caddy:2.11.7-alpine" {
				t.Errorf("caddy: variant %q, name %q", f.Variant, f.Vars["name"])
			}
		case own:
			if f.Variant != "" {
				t.Errorf("the team's own image is rebuilt, not pulled: %q", f.Variant)
			}
		}
	}
}

func TestPublishedImages(t *testing.T) {
	for img, want := range map[string]bool{
		"caddy:2.11.7-alpine":             true,
		"bitnami/redis:7.2":               true,
		"docker.io/library/nginx:1.27":    true,
		"ghcr.io/acme/checkout-api:3.8.1": false,
		"registry.acme.test:5000/shop:2":  false,
		"localhost/shop:dev":              false,
		"kiyesi-caddy:local":              false,
	} {
		if got := publishedImage(img); got != want {
			t.Errorf("%s: %v, want %v", img, got, want)
		}
	}
}

func TestFlawWordsStopAtThree(t *testing.T) {
	fs := []flaw{{"A", "a", "1", "2"}, {"B", "b", "1", "2"}, {"C", "c", "1", "2"}, {"D", "d", "1", "2"}, {"E", "e", "1", "2"}}
	if got := flawWords(fs); got != "a 1 to 2 (A), b 1 to 2 (B), c 1 to 2 (C), and 2 more" {
		t.Errorf("got %q", got)
	}
}
