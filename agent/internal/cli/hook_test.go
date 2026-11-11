package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/githook"
)

const hookListBody = `{"sha":"abc","fetchedAt":"2026-11-10T09:00:00.000Z"}` + "\n" + `["MAL-2025-1","npm","left-pad-x",1,[],[]]` + "\n"

const evilPackage = "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"left-pad-x\": \"^1.0.1\"\n  }\n}\n"

// hookEnv keeps git from this machine's settings and points the list at a
// test server and a test cache folder.
func hookEnv(t *testing.T, api string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": empty, "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
		"GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
		"KIYESI_API": api, "KIYESI_CACHE": cache, "NO_COLOR": "1",
	} {
		t.Setenv(k, v)
	}
	return cache
}

func listSrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != githook.ListPath {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write([]byte(hookListBody))
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(b.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitTry(dir, nil, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(out)
}

func gitTry(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeRepoFile(t *testing.T, dir, name, text string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// remoteAndClone makes a bare remote with one commit and a clone of it.
func remoteAndClone(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	gitIn(t, src, "init", "-q", "-b", "main")
	writeRepoFile(t, src, "package.json", "{\n  \"name\": \"app\"\n}\n")
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "first")
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitIn(t, src, "clone", "-q", "--bare", src, remote)
	dir := filepath.Join(t.TempDir(), "work")
	gitIn(t, src, "clone", "-q", remote, dir)
	return dir
}

// The week's "done when": a push adding a known-malicious package is
// stopped on the developer's machine with the fix shown; --no-verify
// still pushes; a clean change pushes.
func TestGitHookStopsAMaliciousPackageEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook runs under sh; Git for Windows' sh is not on the test machines")
	}
	srv := listSrv(t)
	hookEnv(t, srv.URL)
	t.Setenv("KIYESI_TEST_AS_KIYESI", "1")
	dir := remoteAndClone(t)

	var out, errOut bytes.Buffer
	if code := Execute([]string{"hook", "install", "--path", dir}, IO{Out: &out, Err: &errOut, Environ: os.Environ()}); code != ExitOK {
		t.Fatalf("install: exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Kiyesi's pre-push hook is installed.") {
		t.Errorf("install said %q", out.String())
	}
	// Install gets the list, so the first push does not wait for it.
	if !strings.Contains(out.String(), "The malicious-package list is ready:") {
		t.Errorf("install did not get the list: %q", out.String())
	}

	writeRepoFile(t, dir, "package.json", evilPackage)
	gitIn(t, dir, "commit", "-q", "-am", "add a package")
	pushed, err := gitTry(dir, nil, "push", "origin", "main")
	if err == nil {
		t.Fatalf("the push went through:\n%s", pushed)
	}
	for _, want := range []string{
		"Kiyesi stopped this push: 1 problem to fix first.",
		"STOP  Malicious package added: left-pad-x ^1.0.1",
		"package.json:4",
		`"left-pad-x": "^1.0.1"`,
		"Fix: Remove left-pad-x from package.json, run npm install",
		"To push anyway, skipping this check: git push --no-verify",
	} {
		if !strings.Contains(pushed, want) {
			t.Errorf("the refused push does not say %q:\n%s", want, pushed)
		}
	}
	t.Logf("a stopped push:\n%s", pushed)
	if remoteHead := gitIn(t, dir, "rev-parse", "origin/main"); remoteHead == gitIn(t, dir, "rev-parse", "HEAD") {
		t.Fatal("the remote has the commit")
	}

	if out, err := gitTry(dir, nil, "push", "--no-verify", "origin", "main"); err != nil {
		t.Fatalf("--no-verify: %v\n%s", err, out)
	}

	writeRepoFile(t, dir, "README.md", "# app\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "readme")
	clean, err := gitTry(dir, nil, "push", "origin", "main")
	if err != nil {
		t.Fatalf("a clean push was refused: %v\n%s", err, clean)
	}
	if !strings.Contains(clean, "Kiyesi checked this push: nothing found.") {
		t.Errorf("clean push said %q", clean)
	}
}

// runHookIn runs kiyesi hook run in dir as git would, with these lines on stdin.
func runHookIn(t *testing.T, dir, stdin string) (int, string) {
	t.Helper()
	t.Chdir(dir)
	var out, errOut bytes.Buffer
	code := Execute([]string{"hook", "run", "origin", "https://example.com/a.git"}, IO{Out: &out, Err: &errOut, Environ: []string{"NO_COLOR=1"}, In: strings.NewReader(stdin)})
	if out.Len() != 0 {
		t.Errorf("hook run wrote to stdout, which git does not show: %q", out.String())
	}
	return code, errOut.String()
}

func badCommit(t *testing.T) (string, string) {
	dir := remoteAndClone(t)
	base := gitIn(t, dir, "rev-parse", "HEAD")
	writeRepoFile(t, dir, "package.json", evilPackage)
	gitIn(t, dir, "commit", "-q", "-am", "add a package")
	head := gitIn(t, dir, "rev-parse", "HEAD")
	return dir, "refs/heads/main " + head + " refs/heads/main " + base + "\n"
}

// Offline with a copy: the copy is used, and its age is said.
func TestHookOfflineUsesTheCopyAndSaysItsAge(t *testing.T) {
	cache := hookEnv(t, "http://127.0.0.1:1")
	if err := os.WriteFile(filepath.Join(cache, githook.ListFile), []byte(hookListBody), 0o600); err != nil {
		t.Fatal(err)
	}
	old := hookNow
	hookNow = func() time.Time { return time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { hookNow = old })
	dir, stdin := badCommit(t)
	code, out := runHookIn(t, dir, stdin)
	if code != ExitFindings || !strings.Contains(out, "Malicious package added: left-pad-x") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "The malicious-package list is 2 days old: Kiyesi could not reach the internet.") {
		t.Errorf("the list's age is not said:\n%s", out)
	}
}

// Offline with no copy: a note, the other rules run, and the push goes on.
func TestHookOfflineWithoutAListLetsThePushGo(t *testing.T) {
	hookEnv(t, "http://127.0.0.1:1")
	dir, stdin := badCommit(t)
	code, out := runHookIn(t, dir, stdin)
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "Kiyesi has no copy of the malicious-package list yet (Kiyesi could not reach the internet), so packages were not checked against it.") {
		t.Errorf("no note:\n%s", out)
	}
}

// Warnings print and the push goes on; a deletion alone checks nothing and
// prints nothing.
func TestHookWarningsAndDeletions(t *testing.T) {
	hookEnv(t, listSrv(t).URL)
	dir := remoteAndClone(t)
	base := gitIn(t, dir, "rev-parse", "HEAD")
	writeRepoFile(t, dir, ".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: someone/action@v1\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "ci")
	head := gitIn(t, dir, "rev-parse", "HEAD")
	code, out := runHookIn(t, dir, "refs/heads/main "+head+" refs/heads/main "+base+"\n")
	if code != ExitOK || !strings.Contains(out, "WARN  Action not pinned to a commit: someone/action@v1") || !strings.Contains(out, "which do not stop it") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "--no-verify") {
		t.Error("a push that goes on is told how to skip the check")
	}
	zero := strings.Repeat("0", 40)
	code, out = runHookIn(t, dir, "(delete) "+zero+" refs/heads/old "+base+"\n")
	if code != ExitOK || out != "" {
		t.Errorf("deletion: exit %d, %q", code, out)
	}
	// What git would never send is not a reason to stop a push.
	code, out = runHookIn(t, dir, "nonsense\n")
	if code != ExitOK || !strings.Contains(out, "Kiyesi did not check this push") {
		t.Errorf("nonsense: exit %d, %q", code, out)
	}
}

func TestHookStatusAndUninstallFromTheCommandLine(t *testing.T) {
	cache := hookEnv(t, "http://127.0.0.1:1")
	if err := os.WriteFile(filepath.Join(cache, githook.ListFile), []byte(hookListBody), 0o600); err != nil {
		t.Fatal(err)
	}
	old, oldExe := hookNow, hookExecutable
	hookNow = func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }
	hookExecutable = func() (string, error) { return "/usr/local/bin/kiyesi", nil }
	t.Cleanup(func() { hookNow, hookExecutable = old, oldExe })
	dir := remoteAndClone(t)
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := Execute(args, IO{Out: &out, Err: &errOut, Environ: []string{"NO_COLOR=1"}})
		return code, out.String() + errOut.String()
	}
	if code, out := run("hook", "status", "--path", dir); code != 0 || !strings.Contains(out, "is not installed") || !strings.Contains(out, "the malicious-package list is 3 hours old") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if code, out := run("hook", "install", "--path", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if code, out := run("hook", "install", "--path", dir); code != 0 || !strings.Contains(out, "already in") {
		t.Errorf("second install: %d %s", code, out)
	}
	code, out := run("hook", "status", "--path", dir, "--json")
	var st struct {
		Installed bool   `json:"installed"`
		Kiyesi    string `json:"kiyesi"`
		Hook      string `json:"hook"`
		List      struct {
			Present   bool   `json:"present"`
			FetchedAt string `json:"fetchedAt"`
		} `json:"list"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil || !st.Installed || st.Kiyesi != "/usr/local/bin/kiyesi" || !st.List.Present || st.List.FetchedAt == "" {
		t.Errorf("status --json: %d %s", code, out)
	}
	if code, out := run("hook", "uninstall", "--path", dir); code != 0 || !strings.Contains(out, "removed") {
		t.Errorf("uninstall: %d %s", code, out)
	}
	if code, out := run("hook", "install", "--path", t.TempDir()); code != ExitUsage || !strings.Contains(out, "not in a git repository") {
		t.Errorf("outside a repository: %d %s", code, out)
	}
}

// Install without the internet: the hook is installed, the person is told
// the list is missing and how to get it, and nothing fails.
func TestHookInstallOfflineSaysTheListIsMissing(t *testing.T) {
	hookEnv(t, "http://127.0.0.1:1")
	dir := remoteAndClone(t)
	var out, errOut bytes.Buffer
	if code := Execute([]string{"hook", "install", "--path", dir}, IO{Out: &out, Err: &errOut, Environ: []string{"NO_COLOR=1"}}); code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Kiyesi's pre-push hook is installed.") ||
		!strings.Contains(out.String(), "Kiyesi could not get the malicious-package list yet (Kiyesi could not reach the internet)") ||
		!strings.Contains(out.String(), "kiyesi hook update") {
		t.Errorf("said:\n%s", out.String())
	}
}

// A timeout is not "no internet": it says how long Kiyesi waited.
func TestWhyNoListSaysATimeoutAsOne(t *testing.T) {
	for failed, want := range map[string]string{
		"could not reach api.kiyesi.dev":            "Kiyesi could not reach the internet",
		"no answer within 3 seconds":                "no answer within 3 seconds; kiyesi hook update waits longer",
		"the list did not arrive within 30 seconds": "the list did not arrive within 30 seconds; kiyesi hook update waits longer",
		"the service answered 503":                  "Kiyesi could not get a newer one: the service answered 503",
	} {
		if got := whyNoList(failed); got != want {
			t.Errorf("%q: %q, want %q", failed, got, want)
		}
	}
}

// A committed hooks folder: install prints the line, and changes nothing.
func TestHookInstallPrintsTheLineForATeamsHooks(t *testing.T) {
	hookEnv(t, "http://127.0.0.1:1")
	dir := remoteAndClone(t)
	writeRepoFile(t, dir, ".githooks/pre-push", "#!/bin/sh\nnpm test\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "hooks")
	gitIn(t, dir, "config", "core.hooksPath", ".githooks")
	var out bytes.Buffer
	if code := Execute([]string{"hook", "install", "--path", dir}, IO{Out: &out, Err: &out, Environ: []string{"NO_COLOR=1"}}); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "so Kiyesi changed nothing") || !strings.Contains(out.String(), "Add this line to .githooks/pre-push") || !strings.Contains(out.String(), githook.TeamLine) {
		t.Errorf("said:\n%s", out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".githooks", "pre-push")); string(b) != "#!/bin/sh\nnpm test\n" {
		t.Error("the team's hook changed")
	}
	if s := gitIn(t, dir, "status", "--porcelain"); s != "" {
		t.Errorf("the repository changed: %s", s)
	}
}

func TestHookUpdate(t *testing.T) {
	cache := hookEnv(t, listSrv(t).URL)
	var out, errOut bytes.Buffer
	if code := Execute([]string{"hook", "update"}, IO{Out: &out, Err: &errOut}); code != 0 || !strings.Contains(out.String(), "The malicious-package list is current") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	if b, _ := os.ReadFile(filepath.Join(cache, githook.ListFile)); string(b) != hookListBody {
		t.Errorf("kept %q", b)
	}
	t.Setenv("KIYESI_API", "http://127.0.0.1:1")
	out.Reset()
	errOut.Reset()
	if code := Execute([]string{"hook", "update"}, IO{Out: &out, Err: &errOut}); code != ExitNoAccess || !strings.Contains(errOut.String(), "The copy it has is used") {
		t.Errorf("offline update: exit %d: %s", code, errOut.String())
	}
}
