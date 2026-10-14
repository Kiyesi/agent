package checks

import (
	"context"
	"testing"
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
