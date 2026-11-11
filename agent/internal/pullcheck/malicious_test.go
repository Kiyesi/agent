package pullcheck

import (
	"strings"
	"testing"
)

// A known-malicious package added in each language's manifests and
// lockfiles is found, on the line that names it.
func TestMaliciousInEveryLanguage(t *testing.T) {
	list := testList(t)
	for _, c := range []struct {
		path, after string
		eco, name   string
		version     string
		line        int
	}{
		{"package.json", "{\n  \"dependencies\": {\n    \"express\": \"^4.0.0\",\n    \"left-pad-x\": \"^1.0.1\"\n  }\n}\n", "npm", "left-pad-x", "^1.0.1", 4},
		{"package-lock.json", "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {\"name\": \"app\"},\n    \"node_modules/left-pad-x\": {\n      \"version\": \"1.0.1\",\n      \"resolved\": \"https://registry.npmjs.org/left-pad-x/-/left-pad-x-1.0.1.tgz\"\n    }\n  }\n}\n", "npm", "left-pad-x", "1.0.1", 5},
		{"web/npm-shrinkwrap.json", "{\"lockfileVersion\": 1, \"dependencies\": {\"left-pad-x\": {\"version\": \"2.0.0\"}}}", "npm", "left-pad-x", "2.0.0", 1},
		{"yarn.lock", "# yarn lockfile v1\n\nexpress@^4.0.0:\n  version \"4.18.2\"\n\nleft-pad-x@^1.0.0:\n  version \"1.0.1\"\n  resolved \"https://registry.yarnpkg.com/left-pad-x/-/left-pad-x-1.0.1.tgz#abc\"\n", "npm", "left-pad-x", "1.0.1", 6},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad-x@1.0.1:\n    resolution: {integrity: sha512-aaa}\n", "npm", "left-pad-x", "1.0.1", 5},
		{"requirements.txt", "django==4.2.0\nevil-pkg==1.0.0 ; python_version > \"3\"\n", "PyPI", "evil-pkg", "1.0.0", 2},
		{"requirements-dev.txt", "Evil_Pkg[extra]==1.0.0\n", "PyPI", "Evil_Pkg", "1.0.0", 1},
		{"poetry.lock", "[[package]]\nname = \"evil-pkg\"\nversion = \"1.0.0\"\n", "PyPI", "evil-pkg", "1.0.0", 2},
		{"Pipfile.lock", "{\n  \"_meta\": {},\n  \"default\": {\n    \"evil-pkg\": {\n      \"version\": \"==1.0.0\"\n    }\n  }\n}\n", "PyPI", "evil-pkg", "1.0.0", 4},
		{"uv.lock", "version = 1\n\n[[package]]\nname = \"evil.pkg\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n", "PyPI", "evil.pkg", "1.0.0", 4},
		{"go.mod", "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/evil/mod v1.2.3 // indirect\n)\n", "Go", "github.com/evil/mod", "1.2.3", 6},
		{"go.sum", "github.com/evil/mod v1.2.3 h1:abc=\ngithub.com/evil/mod v1.2.3/go.mod h1:def=\n", "Go", "github.com/evil/mod", "1.2.3", 1},
		{"pom.xml", "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.evil</groupId>\n      <artifactId>lib</artifactId>\n      <version>1.0</version>\n    </dependency>\n  </dependencies>\n</project>\n", "Maven", "com.evil:lib", "1.0", 5},
		{"gradle.lockfile", "# comment\ncom.evil:lib:1.0=compileClasspath\n", "Maven", "com.evil:lib", "1.0", 2},
		{"Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    evilgem (0.1.0)\n", "RubyGems", "evilgem", "0.1.0", 4},
		{"Cargo.lock", "[[package]]\nname = \"evil-crate\"\nversion = \"1.5.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n", "crates.io", "evil-crate", "1.5.0", 2},
		{"packages.lock.json", "{\n  \"dependencies\": {\n    \"net8.0\": {\n      \"evil.lib\": {\n        \"type\": \"Direct\",\n        \"resolved\": \"1.0.0\"\n      }\n    }\n  }\n}\n", "NuGet", "evil.lib", "1.0.0", 4},
		{"src/App/App.csproj", "<Project>\n  <ItemGroup>\n    <PackageReference Include=\"Evil.Lib\" Version=\"[1.0.0]\" />\n  </ItemGroup>\n</Project>\n", "NuGet", "Evil.Lib", "1.0.0", 3},
		{"composer.lock", "{\n  \"packages\": [\n    {\n      \"name\": \"evil/pkg\",\n      \"version\": \"v1.0.0\"\n    }\n  ]\n}\n", "Packagist", "evil/pkg", "1.0.0", 4},
	} {
		t.Run(c.path, func(t *testing.T) {
			o := check(t, Input{List: list, Rules: []string{RuleMalicious}, Files: []File{{Path: c.path, Status: "added", After: str(c.after)}}})
			got := only(o, RuleMalicious)
			if len(got) != 1 {
				t.Fatalf("findings = %+v, notes %v", o.Findings, o.Notes)
			}
			f := got[0]
			if f.Package == nil || f.Package.Ecosystem != c.eco || f.Package.Name != c.name || f.Package.Version != c.version {
				t.Errorf("package = %+v", f.Package)
			}
			if f.Start != c.line || f.End < f.Start {
				t.Errorf("lines %d-%d, want from %d", f.Start, f.End, c.line)
			}
			if f.Severity != "critical" || f.Conclusion != "failure" || len(f.Reports) == 0 || len(f.Fingerprint) != 64 {
				t.Errorf("finding = %+v", f)
			}
			if f.Snippet == "" || !strings.Contains(f.Fix, "see MAL-2025-") || !strings.Contains(f.How, c.path) {
				t.Errorf("snippet %q, how %q, fix %q", f.Snippet, f.How, f.Fix)
			}
			if len(o.Languages) != 1 || o.Languages[0] != c.eco {
				t.Errorf("languages = %v", o.Languages)
			}
		})
	}
}

// A package already there before the change, a version the list does not
// cover, a range the list does not cover and an unpinned requirement are
// not findings.
func TestMaliciousNotFound(t *testing.T) {
	list := testList(t)
	lock := "{\"lockfileVersion\": 3, \"packages\": {\"node_modules/left-pad-x\": {\"version\": \"1.0.1\"}}}"
	for name, f := range map[string]File{
		"already there": {Path: "package-lock.json", Status: "modified", Before: str(lock), After: str(lock)},
		"not covered":   {Path: "Cargo.lock", Status: "added", After: str("[[package]]\nname = \"evil-crate\"\nversion = \"2.0.0\"\n")},
		"range":         {Path: "requirements.txt", Status: "added", After: str("evil-pkg>=1.0\n")},
		"other version": {Path: "Pipfile.lock", Status: "added", After: str(`{"default": {"evil-pkg": {"version": "==1.0.1"}}}`)},
		"clean":         {Path: "package.json", Status: "added", After: str(`{"dependencies": {"left-pad": "1.3.0"}}`)},
	} {
		o := check(t, Input{List: list, Rules: []string{RuleMalicious}, Files: []File{f}})
		if len(o.Findings) != 0 {
			t.Errorf("%s: findings = %+v", name, o.Findings)
		}
	}
}

// The list's age is a note, and its time is given; a missing list is a
// note and the other rules still run.
func TestMaliciousListNotes(t *testing.T) {
	f := File{Path: "package.json", Status: "added", After: str(`{"dependencies": {"left-pad-x": "1.0.1"}}`)}
	o := check(t, Input{List: testList(t), Rules: []string{RuleMalicious}, Files: []File{f}})
	if o.ListFetchedAt != "2026-11-10T09:00:00Z" || len(o.Notes) != 1 || o.Notes[0] != "The malicious-package list is from 2026-11-10 09:00 UTC." {
		t.Errorf("listFetchedAt %q, notes %v", o.ListFetchedAt, o.Notes)
	}
	// Two reports name the same version: both are listed.
	if got := only(o, RuleMalicious); len(got) != 1 || strings.Join(got[0].Reports, ",") != "MAL-2025-1,MAL-2025-9" {
		t.Errorf("findings = %+v", got)
	}
	hidden := File{Path: "a.js", Status: "added", Patch: "@@ -0,0 +1 @@\n+const a = 1;\u202e\n"}
	o = check(t, Input{List: "/nonexistent/list.jsonl", Rules: all(), Files: []File{f, hidden}})
	if len(only(o, RuleMalicious)) != 0 || len(only(o, RuleHidden)) != 1 {
		t.Errorf("findings = %+v", o.Findings)
	}
	if len(o.Notes) != 1 || !strings.Contains(o.Notes[0], "missing") || o.ListFetchedAt != "" {
		t.Errorf("notes = %v", o.Notes)
	}
}

// The fix names the manifest and the lockfile, and the command.
func TestMaliciousWords(t *testing.T) {
	o := check(t, Input{List: testList(t), Rules: []string{RuleMalicious}, Files: []File{{
		Path: "package-lock.json", Status: "added",
		After: str(`{"lockfileVersion": 3, "packages": {"node_modules/left-pad-x": {"version": "1.0.2"}}}`),
	}}})
	f := only(o, RuleMalicious)
	if len(f) != 1 {
		t.Fatalf("findings = %+v", o.Findings)
	}
	want := "Remove left-pad-x from package.json and package-lock.json, run npm install, and check any machine that installed it: see MAL-2025-1."
	if f[0].Fix != want || f[0].Title != "Malicious package added: left-pad-x 1.0.2" {
		t.Errorf("title %q\nfix %q\nwant %q", f[0].Title, f[0].Fix, want)
	}
}

// The fingerprint is the package, not where it is: the same package on
// another line, or in another file, keeps it; another version changes it.
func TestMaliciousFingerprint(t *testing.T) {
	list := testList(t)
	fp := func(after string) string {
		o := check(t, Input{List: list, Rules: []string{RuleMalicious}, Files: []File{{Path: "package-lock.json", Status: "added", After: str(after)}}})
		if len(o.Findings) != 1 {
			t.Fatalf("findings = %+v", o.Findings)
		}
		return o.Findings[0].Fingerprint
	}
	a := fp(`{"packages": {"node_modules/left-pad-x": {"version": "1.0.1"}}}`)
	b := fp("{\n\n\n\"packages\": {\"node_modules/a\": {\"version\": \"1.0.0\"}, \"node_modules/left-pad-x\": {\"version\": \"1.0.1\"}}}")
	c := fp(`{"packages": {"node_modules/left-pad-x": {"version": "1.0.3"}}}`)
	if a != b || a == c {
		t.Errorf("fingerprints %s %s %s", a, b, c)
	}
}
