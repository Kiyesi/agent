package pullcheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func str(s string) *string { return &s }

// testList writes a malicious-package list file with these entries.
func testList(t *testing.T) string {
	t.Helper()
	lines := []string{
		`{"sha":"abc","fetchedAt":"2026-11-10T09:00:00.000Z"}`,
		`["MAL-2025-1","npm","left-pad-x",1,[],[]]`,
		`["MAL-2025-2","PyPI","evil-pkg",0,["1.0.0"],[]]`,
		`["MAL-2025-3","Go","github.com/evil/mod",1,[],[]]`,
		`["MAL-2025-4","Maven","com.evil:lib",1,[],[]]`,
		`["MAL-2025-5","RubyGems","evilgem",1,[],[]]`,
		`["MAL-2025-6","crates.io","evil-crate",0,[],[{"introduced":"0","fixed":"2.0.0"}]]`,
		`["MAL-2025-7","NuGet","Evil.Lib",1,[],[]]`,
		`["MAL-2025-8","Packagist","evil/pkg",1,[],[]]`,
		`["MAL-2025-9","npm","left-pad-x",0,["1.0.1"],[]]`,
		`not a line of the list`,
	}
	p := filepath.Join(t.TempDir(), "malicious.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func check(t *testing.T, in Input) Output {
	t.Helper()
	if err := Validate(in); err != nil {
		t.Fatal(err)
	}
	return Check(context.Background(), in)
}

// only is the findings of one rule.
func only(o Output, rule string) []Finding {
	var out []Finding
	for _, f := range o.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func skippedWhy(o Output, path string) string {
	for _, s := range o.Skipped {
		if s.Path == path {
			return s.Why
		}
	}
	return ""
}

func all() []string { return append([]string{}, Rules...) }
