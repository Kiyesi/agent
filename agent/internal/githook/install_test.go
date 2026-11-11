package githook

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var ctx = context.Background()

// The script is plain sh with LF line ends, runs kiyesi by the path
// recorded, and quotes a Windows path with spaces so Git for Windows' sh
// reads it as one word.
func TestScriptText(t *testing.T) {
	s := Script(`C:\Program Files\Kiyesi's tools\kiyesi.exe`)
	if strings.Contains(s, "\r") {
		t.Fatal("the script has a CR: Git for Windows' sh would read $'\\r' in every word")
	}
	if !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Fatalf("no sh line: %q", s[:20])
	}
	if !strings.Contains(s, `kiyesi='C:/Program Files/Kiyesi'\''s tools/kiyesi.exe'`+"\n") {
		t.Errorf("the path is not quoted with forward slashes:\n%s", s)
	}
	if strings.Contains(s, `\P`) || strings.Contains(s, `\k`) {
		t.Error("a backslash is left in the path")
	}
	for _, want := range []string{
		`"$kiyesi" hook run "$@"`, `[ $? -ne 1 ] || exit 1`, `"$previous" "$@" <"$input"`,
		`cat >"$input"`, `trap 'rm -f "$input"' EXIT`, "git push --no-verify", PreviousName,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script has no %q", want)
		}
	}
	// Only sh: no bash words.
	for _, bashism := range []string{"[[", "$'", "function ", "local ", "<<<", "pipefail"} {
		if strings.Contains(s, bashism) {
			t.Errorf("the script uses %q, which plain sh does not have", bashism)
		}
	}
	if got := recordedKiyesi([]byte(s)); got != filepath.FromSlash(`C:/Program Files/Kiyesi's tools/kiyesi.exe`) {
		t.Errorf("recorded path read back as %q", got)
	}
	if !IsKiyesis([]byte(s)) || IsKiyesis([]byte("#!/bin/sh\nnpm test\n")) {
		t.Error("IsKiyesis is wrong")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		out, err := exec.Command(sh, "-n", "-c", s).CombinedOutput() // #nosec G204 -- the test's own script, parsed only
		if err != nil {
			t.Errorf("sh -n: %v\n%s", err, out)
		}
	}
}

// An earlier hook is kept, run after Kiyesi's with the same arguments and
// stdin, and put back byte for byte, with its mode, by uninstall.
func TestInstallKeepsChainsAndRestoresAnEarlierHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("runs the hook with sh")
	}
	dir := newRepo(t)
	hooks := filepath.Join(dir, ".git", "hooks")
	logs := t.TempDir()
	earlier := "#!/bin/sh\n# the team's own check\necho \"$@\" > '" + logs + "/prev-args'\ncat > '" + logs + "/prev-stdin'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-push"), []byte(earlier), 0o700); err != nil {
		t.Fatal(err)
	}
	// A fake kiyesi that records what it was given and exits with $CODE.
	fake := filepath.Join(t.TempDir(), "kiyesi tool", "kiyesi")
	if err := os.MkdirAll(filepath.Dir(fake), 0o750); err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- a test program
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"$@\" > '"+logs+"/k-args'\ncat > '"+logs+"/k-stdin'\nexit ${CODE:-0}\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	res, err := Install(ctx, dir, fake)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "installed" || res.Previous != filepath.Join(realPath(hooks), PreviousName) {
		t.Fatalf("result = %+v", res)
	}
	kept, _ := os.ReadFile(filepath.Join(hooks, PreviousName))
	if string(kept) != earlier {
		t.Fatal("the earlier hook changed when it was kept")
	}
	// Twice is the same as once.
	again, err := Install(ctx, dir, fake)
	if err != nil || again.Action != "unchanged" {
		t.Fatalf("second install: %+v, %v", again, err)
	}
	if kept2, _ := os.ReadFile(filepath.Join(hooks, PreviousName)); string(kept2) != earlier {
		t.Fatal("a second install touched the earlier hook")
	}

	tmp := t.TempDir()
	stdin := "refs/heads/main " + strings.Repeat("a", 40) + " refs/heads/main " + zero + "\n"
	runHook := func(code string) (int, string) {
		cmd := exec.Command(filepath.Join(hooks, "pre-push"), "origin", "git@example.com:a/b.git") // #nosec G204 -- the hook under test
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(), "CODE="+code, "TMPDIR="+tmp)
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(logs, name))
		return string(b)
	}
	if code, out := runHook("0"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if read("k-args") != "hook run origin git@example.com:a/b.git\n" || read("k-stdin") != stdin {
		t.Errorf("kiyesi got %q and %q", read("k-args"), read("k-stdin"))
	}
	if read("prev-args") != "origin git@example.com:a/b.git\n" || read("prev-stdin") != stdin {
		t.Errorf("the earlier hook got %q and %q", read("prev-args"), read("prev-stdin"))
	}
	// kiyesi saying stop stops the push, and the earlier hook does not run.
	_ = os.Remove(filepath.Join(logs, "prev-args"))
	if code, _ := runHook("1"); code != 1 {
		t.Errorf("a stop from kiyesi exits %d", code)
	}
	if read("prev-args") != "" {
		t.Error("the earlier hook ran after kiyesi stopped the push")
	}
	// Kiyesi's own trouble (any other code) never stops a push.
	if code, out := runHook("2"); code != 0 {
		t.Errorf("kiyesi's trouble stopped the push: exit %d: %s", code, out)
	}
	// The copy of stdin is removed each time.
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("left in the temp folder: %v", left)
	}

	st, err := Status(ctx, dir)
	if err != nil || !st.Installed || st.Kiyesi != fake || !st.KiyesiFound || st.Previous == "" {
		t.Errorf("status = %+v, %v", st, err)
	}

	un, err := Uninstall(ctx, dir)
	if err != nil || un.Action != "removed" || un.Previous == "" {
		t.Fatalf("uninstall = %+v, %v", un, err)
	}
	back, _ := os.ReadFile(filepath.Join(hooks, "pre-push"))
	fi, _ := os.Stat(filepath.Join(hooks, "pre-push"))
	if string(back) != earlier || fi.Mode().Perm() != 0o700 {
		t.Errorf("the earlier hook came back as %q, mode %v", back, fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(hooks, PreviousName)); !os.IsNotExist(err) {
		t.Error("the kept copy is still there")
	}
	// Uninstalling again removes nothing that is not Kiyesi's.
	if un, _ := Uninstall(ctx, dir); un.Action != "absent" {
		t.Errorf("second uninstall: %+v", un)
	}
	if b, _ := os.ReadFile(filepath.Join(hooks, "pre-push")); string(b) != earlier {
		t.Error("uninstall touched a hook that is not Kiyesi's")
	}
}

// Without kiyesi anywhere, the hook says so and the push goes on.
func TestHookWithoutKiyesiLetsThePushGo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("runs the hook with sh")
	}
	dir := newRepo(t)
	if _, err := Install(ctx, dir, "/nowhere/kiyesi"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(dir, ".git", "hooks", "pre-push"), "origin", "x") // #nosec G204 -- the hook under test
	cmd.Stdin = strings.NewReader("")
	cmd.Env = append(os.Environ(), "PATH=/usr/bin:/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "kiyesi was not found") {
		t.Errorf("output %q", out)
	}
}

// A fresh install with no earlier hook writes a runnable hook, and
// uninstall leaves no hook.
func TestInstallFreshAndUninstall(t *testing.T) {
	dir := newRepo(t)
	res, err := Install(ctx, dir, "/usr/local/bin/kiyesi")
	if err != nil || res.Action != "installed" || res.Previous != "" {
		t.Fatalf("%+v %v", res, err)
	}
	b, err := os.ReadFile(res.Hook)
	if err != nil || !bytes.Equal(b, []byte(Script("/usr/local/bin/kiyesi"))) {
		t.Fatalf("hook = %q, %v", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(res.Hook)
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("the hook is not runnable: %v", fi.Mode())
		}
	}
	// A new kiyesi path updates the hook in place.
	if res, _ := Install(ctx, dir, "/opt/kiyesi"); res.Action != "updated" {
		t.Errorf("second install with a new path: %+v", res)
	}
	if un, _ := Uninstall(ctx, dir); un.Action != "removed" || un.Previous != "" {
		t.Errorf("%+v", un)
	}
	if _, err := os.Stat(res.Hook); !os.IsNotExist(err) {
		t.Error("the hook is still there")
	}
}

// A hooks folder committed in the repository (Husky) is the team's:
// install edits nothing and gives the line to add.
func TestTrackedHooksPathIsNotEdited(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, ".githooks/pre-push", "#!/bin/sh\nnpm test\n")
	commit(t, dir, "hooks")
	run(t, dir, "config", "core.hooksPath", ".githooks")
	before := snapshot(t, dir)
	res, err := Install(ctx, dir, "/usr/local/bin/kiyesi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "team" || res.Line != TeamLine || res.Hook != filepath.Join(realPath(dir), ".githooks", "pre-push") || res.LinePresent {
		t.Errorf("result = %+v", res)
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("install changed files:\n%s\n---\n%s", before, after)
	}
	if un, _ := Uninstall(ctx, dir); un.Action != "team" || snapshot(t, dir) != before {
		t.Errorf("uninstall = %+v, or changed files", un)
	}
	// Once the line is added, status says the push is checked.
	write(t, dir, ".githooks/pre-push", "#!/bin/sh\n"+TeamLine+"\nnpm test\n")
	st, err := Status(ctx, dir)
	if err != nil || !st.Installed || !st.LinePresent || !st.Repo.Team {
		t.Errorf("status = %+v, %v", st, err)
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		if out, err := exec.Command(sh, "-n", "-e", "-c", TeamLine).CombinedOutput(); err != nil { // #nosec G204 -- the test's own line, parsed only
			t.Errorf("the line does not parse: %v %s", err, out)
		}
	}
}

// Husky 9 sets core.hooksPath to .husky/_; the line goes in .husky/pre-push.
func TestHuskyLineGoesInItsOwnHook(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, ".husky/_/.gitignore", "*\n")
	write(t, dir, ".husky/_/h", "#!/bin/sh\n")
	run(t, dir, "config", "core.hooksPath", ".husky/_")
	res, err := Install(ctx, dir, "/usr/local/bin/kiyesi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "team" || res.Hook != filepath.Join(realPath(dir), ".husky", "pre-push") {
		t.Errorf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, ".husky", "_", "pre-push")); !os.IsNotExist(err) {
		t.Error("Kiyesi wrote into Husky's folder")
	}
}

// A core.hooksPath outside the repository (a person's own folder of hooks
// for every repository) is theirs: the hook goes there, chained, and
// install says it covers every repository that uses the folder.
func TestHooksPathOutsideTheRepository(t *testing.T) {
	dir := newRepo(t)
	shared := t.TempDir()
	earlier := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shared, "pre-push"), []byte(earlier), 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "config", "core.hooksPath", shared)
	res, err := Install(ctx, dir, "/usr/local/bin/kiyesi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "installed" || !res.Repo.Shared || res.Repo.Team || res.Hook != filepath.Join(realPath(shared), "pre-push") {
		t.Fatalf("result = %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(shared, PreviousName)); string(b) != earlier {
		t.Error("the earlier hook was not kept")
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "hooks", "pre-push")); !os.IsNotExist(err) {
		t.Error("a hook was written where git would not run it")
	}
}

// In a worktree, git runs the main repository's hooks: install finds them.
func TestInstallInAWorktree(t *testing.T) {
	dir := newRepo(t)
	wt := filepath.Join(t.TempDir(), "wt")
	run(t, dir, "worktree", "add", "-q", "-b", "feature", wt)
	res, err := Install(ctx, wt, "/usr/local/bin/kiyesi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Hook != filepath.Join(realPath(dir), ".git", "hooks", "pre-push") {
		t.Errorf("hook at %s", res.Hook)
	}
}

// When both a foreign hook and a kept one are there, install refuses
// rather than lose either.
func TestInstallNeverLosesAHook(t *testing.T) {
	dir := newRepo(t)
	hooks := filepath.Join(dir, ".git", "hooks")
	for _, n := range []string{"pre-push", PreviousName} {
		if err := os.WriteFile(filepath.Join(hooks, n), []byte("#!/bin/sh\n# "+n+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(ctx, dir, "/usr/local/bin/kiyesi"); err == nil || !strings.Contains(err.Error(), "already holds an earlier hook") {
		t.Fatalf("err = %v", err)
	}
	for _, n := range []string{"pre-push", PreviousName} {
		if b, _ := os.ReadFile(filepath.Join(hooks, n)); string(b) != "#!/bin/sh\n# "+n+"\n" {
			t.Errorf("%s changed", n)
		}
	}
}

func TestNotARepository(t *testing.T) {
	isolateGit(t)
	if _, err := Install(ctx, t.TempDir(), "/usr/local/bin/kiyesi"); err == nil || !strings.Contains(err.Error(), "not in a git repository") {
		t.Errorf("err = %v", err)
	}
}

// snapshot lists every file under dir with its content, but git's own folder.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() && fi.Name() == ".git" {
			return filepath.SkipDir
		}
		if !fi.IsDir() {
			data, _ := os.ReadFile(p) // #nosec G304 -- the test's own files
			b.WriteString(p + " " + fi.Mode().String() + "\n" + string(data) + "\n")
		}
		return nil
	})
	return b.String()
}
