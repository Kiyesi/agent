package packs

import (
	"os"
	"testing"
)

func TestEnglishLoads(t *testing.T) {
	p, err := English()
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalChecks != 22 {
		t.Errorf("total_checks = %d, want 22", p.TotalChecks)
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
