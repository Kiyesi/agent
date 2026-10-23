package packs

import (
	"os"
	"strings"
	"testing"
)

func TestEnglishLoads(t *testing.T) {
	p, err := English()
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalChecks != 24 {
		t.Errorf("total_checks = %d, want 24", p.TotalChecks)
	}
	if p.Skips["needs-root"] == "" {
		t.Error("the needs-root skip line is missing")
	}
}

// The embedded copy must match packs/ at the repository root.
func TestEmbeddedCopyIsCurrent(t *testing.T) {
	src, err := os.ReadFile("../../../packs/checks/en.yaml")
	if err != nil {
		t.Skip("repository root not available:", err)
	}
	if string(src) != string(checksEN) {
		t.Fatal("agent/internal/packs/data/checks.en.yaml is out of date: run go generate ./... in agent/")
	}
}

func TestFill(t *testing.T) {
	got := Fill("Port {port} on {host}, {missing}", map[string]string{"port": "6379", "host": "a"})
	if want := "Port 6379 on a, {missing}"; got != want {
		t.Errorf("Fill = %q, want %q", got, want)
	}
	if got := Fill("docker inspect --format '{{json .State}}' {name}", map[string]string{"name": "x"}); got != "docker inspect --format '{{json .State}}' x" {
		t.Errorf("Fill broke a Go template: %q", got)
	}
}

// Counts agree with their words, and a day count reads as people say it.
func TestFillCounts(t *testing.T) {
	for _, c := range []struct{ s, n, want string }{
		{"{count|security update has|security updates have} waited", "1", "1 security update has waited"},
		{"{count|security update has|security updates have} waited", "3", "3 security updates have waited"},
		{"{count|No containers|container|containers} running", "0", "No containers running"},
		{"{count|No containers|container|containers} running", "1", "1 container running"},
		{"{count|No containers|container|containers} running", "4", "4 containers running"},
		{"{count|file|files} checked", "0", "0 files checked"},
		{"expires {count|in}", "0", "expires today"},
		{"expires {count|in}", "1", "expires tomorrow"},
		{"expires {count|in}", "9", "expires in 9 days"},
		{"expired {count|ago}", "0", "expired today"},
		{"expired {count|ago}", "1", "expired yesterday"},
		{"expired {count|ago}", "3", "expired 3 days ago"},
	} {
		if got := Fill(c.s, map[string]string{"count": c.n}); got != c.want {
			t.Errorf("Fill(%q, %s) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
	if got := Fill("{missing|file|files}", nil); got != "{missing|file|files}" {
		t.Errorf("a missing count: %q", got)
	}
}

// No line in the pack says "1 files" or "0 days" any more.
func TestPackCountsAgree(t *testing.T) {
	p, err := English()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"count": "1", "days": "1", "limit": "30", "host": "a", "home": "X", "image": "i", "name": "n"}
	for _, c := range p.Checks {
		lines := []string{c.Passed, c.PassedNone, c.PassedNoHome}
		for _, f := range c.Findings {
			lines = append(lines, f.Sentence)
		}
		for _, l := range lines {
			got := Fill(l, vars)
			for _, bad := range []string{"1 files", "1 days", "1 security updates", "1 critical vulnerabilities", "1 certificates", "1 containers", "1 times", "1 databases", "1 database hosts", "1 backup destinations", "1 outside services"} {
				if strings.Contains(got, bad) {
					t.Errorf("%s: %q", c.ID, got)
				}
			}
		}
	}
}

func TestParseRejectsRootWithoutReason(t *testing.T) {
	_, err := Parse([]byte(`checks:
  - id: a
    name: A
    reads: x
    passed: ok
    root: {needed: sometimes}
`))
	if err == nil {
		t.Fatal("expected an error when a check needs root but gives no reason")
	}
}
