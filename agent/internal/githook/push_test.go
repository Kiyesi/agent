package githook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/pullcheck"
)

// clone makes a bare remote with one commit on main and a clone of it.
func clone(t *testing.T) (string, string) {
	t.Helper()
	src := newRepo(t)
	write(t, src, "package.json", "{\n  \"name\": \"app\",\n  \"dependencies\": {}\n}\n")
	commit(t, src, "package")
	remote := filepath.Join(t.TempDir(), "remote.git")
	run(t, src, "clone", "-q", "--bare", src, remote)
	dir := filepath.Join(t.TempDir(), "work")
	run(t, src, "clone", "-q", remote, dir)
	return remote, dir
}

func upd(ref, local, remote string) Update {
	return Update{LocalRef: "refs/heads/" + ref, LocalSHA: local, RemoteRef: "refs/heads/" + ref, RemoteSHA: remote}
}

func rules(rep Report, rule string) []pullcheck.Finding {
	var out []pullcheck.Finding
	for _, f := range rep.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestParseUpdates(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 64)
	got, err := ParseUpdates(strings.NewReader("refs/heads/main " + a + " refs/heads/main " + zero + "\r\n\n(delete) " + zero + " refs/heads/old " + b + "\n"))
	if err != nil || len(got) != 2 || got[0].LocalSHA != a || got[1].RemoteSHA != b || got[1].LocalRef != "(delete)" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"refs/heads/main --output=x refs/heads/main " + zero, "a b c", "x " + a + " y " + a + " z"} {
		if _, err := ParseUpdates(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A push to an existing branch is compared with the remote's commit.
func TestPushAddingAMaliciousPackageStops(t *testing.T) {
	_, dir := clone(t)
	before := run(t, dir, "rev-parse", "HEAD")
	write(t, dir, "package.json", evilPackageJSON)
	head := commit(t, dir, "add a package")
	rep := CheckPush(ctx, dir, "origin", []Update{upd("main", head, before)}, testList(t))
	got := rules(rep, pullcheck.RuleMalicious)
	if len(got) != 1 || !rep.Stop || got[0].File != "package.json" || got[0].Start != 4 || !strings.Contains(got[0].Fix, "Remove left-pad-x") {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Refs) != 1 || rep.Refs[0].Base != before || rep.Refs[0].Files != 1 {
		t.Errorf("refs = %+v", rep.Refs)
	}
}

// A new branch is compared with where it leaves the remote's main branch:
// what main already had is not reported again.
func TestNewBranchComparedWithTheMergeBase(t *testing.T) {
	remote, dir := clone(t)
	// main gets the bad package on the remote first (pushed without the hook).
	write(t, dir, "package.json", evilPackageJSON)
	commit(t, dir, "bad")
	run(t, dir, "push", "-q", "origin", "main")
	run(t, dir, "remote", "set-head", "origin", "main")
	run(t, dir, "checkout", "-q", "-b", "feature")
	write(t, dir, "src/a.js", "console.log('hi')\n")
	head := commit(t, dir, "feature")
	rep := CheckPush(ctx, dir, "origin", []Update{upd("feature", head, zero)}, testList(t))
	if len(rep.Findings) != 0 || rep.Stop {
		t.Errorf("reported what main already had: %+v", rep.Findings)
	}
	if rep.Refs[0].Files != 1 {
		t.Errorf("refs = %+v", rep.Refs)
	}
	_ = remote
}

// A branch with no history in common with the remote is checked whole,
// within the limits, and says so.
func TestNewBranchWithNoCommonHistory(t *testing.T) {
	isolateGit(t)
	dir := t.TempDir()
	run(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "package.json", evilPackageJSON)
	head := commit(t, dir, "first")
	rep := CheckPush(ctx, dir, "origin", []Update{upd("main", head, zero)}, testList(t))
	if !rep.Stop || len(rules(rep, pullcheck.RuleMalicious)) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "shares no history with the remote's main branch, so all its files were checked, up to 300 files and 5 MB") {
		t.Errorf("notes = %v", rep.Notes)
	}
}

// Deleting a branch checks nothing.
func TestDeletedBranchIsNotChecked(t *testing.T) {
	_, dir := clone(t)
	old := run(t, dir, "rev-parse", "HEAD")
	rep := CheckPush(ctx, dir, "origin", []Update{{LocalRef: "(delete)", LocalSHA: zero, RemoteRef: "refs/heads/old", RemoteSHA: old}}, testList(t))
	if len(rep.Refs) != 0 || len(rep.Findings) != 0 || rep.Stop {
		t.Errorf("report = %+v", rep)
	}
}

// A force push is compared with the commit it replaces, when this clone
// has it; else with where it leaves main.
func TestForcePush(t *testing.T) {
	_, dir := clone(t)
	base := run(t, dir, "rev-parse", "HEAD")
	write(t, dir, "notes.txt", "one\n")
	replaced := commit(t, dir, "to be replaced")
	run(t, dir, "push", "-q", "origin", "main")
	run(t, dir, "reset", "-q", "--hard", base)
	write(t, dir, "package.json", evilPackageJSON)
	head := commit(t, dir, "rewritten")
	rep := CheckPush(ctx, dir, "origin", []Update{upd("main", head, replaced)}, testList(t))
	if !rep.Stop || rep.Refs[0].Base != replaced {
		t.Fatalf("report = %+v", rep)
	}
	// The remote's commit is one this clone never saw.
	unknown := strings.Repeat("c", 40)
	rep = CheckPush(ctx, dir, "origin", []Update{upd("main", head, unknown)}, testList(t))
	if !rep.Stop || !strings.Contains(strings.Join(rep.Notes, " "), "has not fetched") {
		t.Errorf("report = %+v", rep)
	}
}

// Several branches in one push: each is checked, and a problem in two of
// them is listed once.
func TestSeveralBranchesInOnePush(t *testing.T) {
	_, dir := clone(t)
	base := run(t, dir, "rev-parse", "HEAD")
	write(t, dir, "package.json", evilPackageJSON)
	a := commit(t, dir, "a")
	run(t, dir, "checkout", "-q", "-b", "b")
	write(t, dir, "src/hidden.js", "const a = 'x\u202ey';\n")
	b := commit(t, dir, "b")
	rep := CheckPush(ctx, dir, "origin", []Update{upd("main", a, base), upd("b", b, zero)}, testList(t))
	if len(rep.Refs) != 2 {
		t.Fatalf("refs = %+v", rep.Refs)
	}
	if n := len(rules(rep, pullcheck.RuleMalicious)); n != 1 {
		t.Errorf("malicious findings = %d, want 1", n)
	}
	if n := len(rules(rep, pullcheck.RuleHidden)); n != 1 {
		t.Errorf("hidden findings = %d, want 1: %+v", n, rep.Findings)
	}
}

// Install scripts and workflow advice warn; the push goes on.
func TestWarningsDoNotStop(t *testing.T) {
	_, dir := clone(t)
	base := run(t, dir, "rev-parse", "HEAD")
	write(t, dir, ".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: someone/action@v1\n")
	head := commit(t, dir, "ci")
	rep := CheckPush(ctx, dir, "origin", []Update{upd("main", head, base)}, testList(t))
	if len(rules(rep, pullcheck.RuleWorkflow)) == 0 || rep.Stop {
		t.Errorf("report = %+v", rep)
	}
}

// Renames, deletions, binary files, odd names and a lockfile are read as
// the service reads them.
func TestChangedFilesShapes(t *testing.T) {
	_, dir := clone(t)
	write(t, dir, "old name.js", strings.Repeat("line\n", 20))
	write(t, dir, "gone.txt", "bye\n")
	base := commit(t, dir, "files")
	run(t, dir, "mv", "old name.js", "new \"name\".js")
	run(t, dir, "rm", "-q", "gone.txt")
	if err := os.WriteFile(filepath.Join(dir, "img.png"), []byte{0x89, 'P', 'N', 'G', 0, 0, 1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "package.json", evilPackageJSON)
	// A file the repository says not to diff is still read.
	write(t, dir, ".gitattributes", "*.min.js -diff\nsneaky.js binary\n")
	write(t, dir, "sneaky.js", "eval(atob('x'))\n")
	head := commit(t, dir, "shapes")
	// A person's diff settings do not change what is read.
	order := filepath.Join(t.TempDir(), "order")
	if err := os.WriteFile(order, []byte("package.json\n*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"diff.noprefix", "true"}, {"diff.mnemonicPrefix", "true"}, {"diff.orderFile", order}, {"color.diff", "always"}, {"diff.external", "false"}} {
		run(t, dir, "config", kv[0], kv[1])
	}
	files, skipped, notes := changedFiles(ctx, dir, base, head)
	if len(notes) != 0 || len(skipped) != 0 {
		t.Fatalf("skipped %v notes %v", skipped, notes)
	}
	by := map[string]pullcheck.File{}
	for _, f := range files {
		by[f.Path] = f
	}
	if f := by[`new "name".js`]; f.Status != "renamed" || f.Previous != "old name.js" {
		t.Errorf("rename = %+v", f)
	}
	if f := by["gone.txt"]; f.Status != "removed" || !strings.HasPrefix(f.Patch, "@@") {
		t.Errorf("removed = %+v", f)
	}
	if f := by["img.png"]; !f.Binary || f.Status != "added" {
		t.Errorf("binary = %+v", f)
	}
	if f := by["sneaky.js"]; f.Binary || !strings.Contains(f.Patch, "+eval(atob('x'))") {
		t.Errorf("a file marked binary in .gitattributes was not read: %+v", f)
	}
	f := by["package.json"]
	if f.Before == nil || f.After == nil || *f.After != evilPackageJSON || !strings.Contains(f.Patch, "+    \"left-pad-x\"") || f.Binary {
		t.Errorf("package.json = %+v", f)
	}
}

// A large push (300 files, 5 MB) is checked within a few seconds, and what
// is over the limits is named.
func TestLargePushIsQuick(t *testing.T) {
	_, dir := clone(t)
	base := run(t, dir, "rev-parse", "HEAD")
	line := strings.Repeat("abcdefghij", 7) + "\n"
	body := strings.Repeat(line, 20000/len(line)) // about 20 KB each, 6 MB in all
	for i := 0; i < 320; i++ {
		write(t, dir, fmt.Sprintf("src/f%03d.js", i), fmt.Sprintf("// %d\n%s", i, body))
	}
	write(t, dir, "package.json", evilPackageJSON)
	head := commit(t, dir, "big")
	start := time.Now()
	rep := CheckPush(ctx, dir, "origin", []Update{upd("main", head, base)}, testList(t))
	took := time.Since(start)
	// The race detector makes the rules many times slower, so the time is
	// held only in an ordinary build (go test ./..., as CI also runs).
	if took > 5*time.Second && !raceEnabled {
		t.Errorf("took %v", took)
	}
	t.Logf("checked in %v, %d skipped", took, len(rep.Skipped))
	why := map[string]int{}
	for _, s := range rep.Skipped {
		why[s.Why]++
	}
	if why["over the file limit"] != 1 || why["over the size limit"] == 0 {
		t.Errorf("skipped = %v", why)
	}
	// package.json sorts first and is still checked.
	if !rep.Stop {
		t.Error("the bad package was not found in a large push")
	}
}
