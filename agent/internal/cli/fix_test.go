package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/send"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// cliHost is the server kiyesi fix changes in these tests. The scan reads
// the same files, so checking again after a fix sees what it changed.
type cliHost struct {
	files map[string][]byte
	modes map[string]fs.FileMode
	ran   []string
	// chmodErr, when set, makes the next change of mode fail.
	chmodErr error
}

type cliInfo struct {
	path string
	mode fs.FileMode
}

func (i cliInfo) Name() string       { return "" }
func (i cliInfo) Size() int64        { return 0 }
func (i cliInfo) Mode() fs.FileMode  { return i.mode }
func (i cliInfo) ModTime() time.Time { return time.Time{} }
func (i cliInfo) IsDir() bool        { return i.mode.IsDir() }
func (i cliInfo) Sys() any           { return &syscall.Stat_t{Ino: cliInode(i.path)} }

func cliInode(p string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(p))
	return h.Sum64()
}

func (h *cliHost) ReadFile(p string) ([]byte, error) {
	if d, ok := h.files[p]; ok {
		return d, nil
	}
	return nil, fs.ErrNotExist
}
func (h *cliHost) Lstat(p string) (fs.FileInfo, error) {
	if _, ok := h.files[p]; !ok {
		for f := range h.files {
			if strings.HasPrefix(f, p+"/") {
				return cliInfo{p, fs.ModeDir | 0o755}, nil
			}
		}
		return nil, fs.ErrNotExist
	}
	return cliInfo{p, h.modes[p]}, nil
}
func (h *cliHost) WriteFile(p string, d []byte, m fs.FileMode) error {
	h.files[p], h.modes[p] = d, m
	return nil
}
func (h *cliHost) Remove(p string) error { delete(h.files, p); return nil }
func (h *cliHost) ChmodFile(p string, want fix.FileID, m fs.FileMode) error {
	if err := h.chmodErr; err != nil {
		h.chmodErr = nil
		return err
	}
	if want.Ino != cliInode(p) {
		return fs.ErrNotExist
	}
	h.modes[p] = m
	return nil
}
func (h *cliHost) Has(name string) bool {
	return name == "sshd" || name == "systemctl" || name == "apt-get"
}
func (h *cliHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	h.ran = append(h.ran, cmd)
	switch cmd {
	case "systemctl is-active ssh", "systemctl is-active fail2ban":
		return []byte("active\n"), nil
	case "sshd -T":
		if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
			return []byte("port 22\npasswordauthentication no\n"), nil
		}
		return []byte("port 22\npasswordauthentication yes\n"), nil
	}
	return nil, nil
}

// fixServer is testSystem with SSH reading sshd_config.d, a user with a
// key, and kiyesi fix allowed to run.
func fixServer(t *testing.T) *cliHost {
	t.Helper()
	testSystem(t)
	h := &cliHost{
		files: map[string][]byte{
			"/etc/ssh/sshd_config":           []byte("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n"),
			"/etc/passwd":                    []byte("ada:x:1000:1000::/home/ada:/bin/bash\n"),
			"/home/ada/.ssh/authorized_keys": []byte("ssh-ed25519 AAAA ada@laptop\n"),
			"/srv/app/.env":                  []byte("DB_PASSWORD=correct-horse-battery\n"),
		},
		modes: map[string]fs.FileMode{"/srv/app/.env": 0o644},
	}
	base := newSystem
	newSystem = func(root bool, stateDir string) *system.System {
		s := base(root, stateDir)
		m := s.FS.(fstest.MapFS)
		for p, d := range h.files {
			m[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Data: d, Mode: h.modes[p]}
		}
		s.OS.ID = "ubuntu"
		return s
	}
	oldHost, oldDir, oldRoot, oldTerm := fixHost, fixStoreDir, fixAsRoot, fixTerminal
	t.Cleanup(func() { fixHost, fixStoreDir, fixAsRoot, fixTerminal = oldHost, oldDir, oldRoot, oldTerm })
	fixHost, fixStoreDir = h, t.TempDir()
	fixAsRoot = func() bool { return true }
	fixTerminal = func(IO) bool { return true }
	t.Setenv("KIYESI_ETC", t.TempDir())
	t.Setenv("KIYESI_STATE", t.TempDir())
	return h
}

func runFixCLI(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args = append(args, "--config", configFlag)
	code := Execute(args, IO{Out: &out, Err: &errOut, Environ: []string{"NO_COLOR=1", "SUDO_USER=ada"}, In: strings.NewReader(input)})
	return code, out.String(), errOut.String()
}

func TestFixListsAsksFixesAndShowsTheGradeMove(t *testing.T) {
	h := fixServer(t)
	code, out, errOut := runFixCLI(t, "y\n", "fix")
	if code != ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Kiyesi can fix 3 things for you:",
		"1. SSH allows password login (ssh-password)",
		"Turns SSH password login off. ada has an SSH key here, so you stay in.",
		"Skipped if ssh-password turns password login off first.",
		// Not needed once passwords are off.
		"– login-protection: Not needed: with SSH password login off, there is no password to guess.",
		"/srv/app/.env holds secrets and every user on this server can read it (secret-files)",
		"✓ SSH password login off  (undo: sudo kiyesi fix undo ",
		"✓ Secret files closed to other users  (undo: sudo kiyesi fix undo ",
		"Checking again…",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "Fix all 3? [y/N/choose]") {
		t.Errorf("not asked: %q", errOut)
	}
	// The grade moved up, seen by the scan after the fix.
	var before, after int
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "→") {
			f := strings.Fields(line)
			// GRADE  X  NN  →  Y  NN/100
			_ = json.Unmarshal([]byte(f[2]), &before)
			_ = json.Unmarshal([]byte(strings.TrimSuffix(f[5], "/100")), &after)
		}
	}
	if before == 0 || after <= before {
		t.Errorf("grade did not go up (%d → %d):\n%s", before, after, out)
	}
	if h.modes["/srv/app/.env"] != 0o640 {
		t.Errorf(".env mode = %o", h.modes["/srv/app/.env"])
	}
	// Not connected: nothing waits to be sent.
	if entries, _ := os.ReadDir(outboxDir()); len(entries) != 0 {
		t.Errorf("an unconnected server queued %d batches", len(entries))
	}
}

func TestFixNoMeansNothingChanges(t *testing.T) {
	h := fixServer(t)
	code, out, _ := runFixCLI(t, "\n", "fix")
	if code != ExitOK || !strings.Contains(out, "Nothing was changed.") {
		t.Fatalf("%d %s", code, out)
	}
	if len(h.ran) > 2 || h.modes["/srv/app/.env"] != 0o644 {
		t.Errorf("changed something: %v %o", h.ran, h.modes["/srv/app/.env"])
	}
	for _, c := range h.ran {
		if !strings.HasPrefix(c, "sshd -T") && !strings.HasPrefix(c, "systemctl is-active") {
			t.Errorf("ran %q before anyone said yes", c)
		}
	}
}

func TestFixChooseOneByOne(t *testing.T) {
	h := fixServer(t)
	code, out, _ := runFixCLI(t, "choose\nn\nn\ny\n", "fix")
	if code != ExitOK || strings.Contains(out, "✓ SSH password login off") || strings.Contains(out, "fail2ban on") || !strings.Contains(out, "✓ Secret files closed") {
		t.Fatalf("%d\n%s", code, out)
	}
	if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
		t.Error("SSH was changed after a no")
	}
}

func TestFixDryRunAndJSONChangeNothing(t *testing.T) {
	h := fixServer(t)
	code, out, _ := runFixCLI(t, "", "fix", "--dry-run")
	if code != ExitOK || !strings.Contains(out, "Nothing was changed. To make these changes: sudo kiyesi fix") {
		t.Fatalf("%d\n%s", code, out)
	}
	code, out, _ = runFixCLI(t, "", "fix", "--dry-run", "--json")
	var plan []fixJSON
	if code != ExitOK || json.Unmarshal([]byte(out), &plan) != nil || len(plan) != 3 || plan[0].Name != "ssh-password" || !plan[0].Undoable {
		t.Fatalf("%d %s", code, out)
	}
	if h.modes["/srv/app/.env"] != 0o644 || len(h.files) != 4 {
		t.Error("a dry run changed something")
	}
	if code, _, errOut := runFixCLI(t, "", "fix", "--json"); code != ExitUsage || !strings.Contains(errOut, "add --dry-run") {
		t.Errorf("--json alone: %d %q", code, errOut)
	}
}

func TestFixOneByName(t *testing.T) {
	h := fixServer(t)
	code, out, errOut := runFixCLI(t, "y\n", "fix", "secret-files")
	if code != ExitOK || strings.Contains(out, "ssh-password") || h.modes["/srv/app/.env"] != 0o640 {
		t.Fatalf("%d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "Make this change? [y/N]") {
		t.Errorf("asked %q", errOut)
	}
	code, out, _ = runFixCLI(t, "", "fix", "certificates")
	if code != ExitOK || !strings.Contains(out, "Nothing to fix for certificates: it passed, or does not apply here.") {
		t.Errorf("%d %s", code, out)
	}
	if code, _, errOut := runFixCLI(t, "", "fix", "everything"); code != ExitUsage || !strings.Contains(errOut, `There is no fix called "everything". The fixes are: certificates, docker-cleanup, firewall,`) {
		t.Errorf("%d %q", code, errOut)
	}
}

func TestFixRefusals(t *testing.T) {
	fixServer(t)
	fixAsRoot = func() bool { return false }
	if code, _, errOut := runFixCLI(t, "", "fix"); code != ExitNoAccess || !strings.Contains(errOut, "Run it with sudo: sudo kiyesi fix") {
		t.Errorf("without root: %d %q", code, errOut)
	}
	fixAsRoot = func() bool { return true }
	fixTerminal = func(IO) bool { return false }
	if code, _, errOut := runFixCLI(t, "", "fix"); code != ExitUsage || !strings.Contains(errOut, "Run it in a terminal, or add --yes") {
		t.Errorf("no terminal: %d %q", code, errOut)
	}
	// A team whose rules allow no tool to change a server.
	if err := os.WriteFile(configFlag, []byte("fix: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runFixCLI(t, "", "fix", "--yes"); code != ExitNoAccess || !strings.Contains(errOut, "kiyesi fix is turned off on this server (fix: off in") {
		t.Errorf("fix off: %d %q", code, errOut)
	}
	if err := os.WriteFile(configFlag, []byte("fix: on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := newSystem
	newSystem = func(root bool, dir string) *system.System {
		s := base(root, dir)
		s.OS = system.OSInfo{ID: "rocky", Name: "Rocky Linux 9"}
		return s
	}
	if code, _, errOut := runFixCLI(t, "", "fix", "--yes"); code != ExitUsage || !strings.Contains(errOut, "works on Debian and Ubuntu for now, and this is Rocky Linux 9") {
		t.Errorf("other system: %d %q", code, errOut)
	}
}

// On a connected server the new scan and what changed wait in the outbox,
// for the agent's service to send within a minute.
func TestFixLeavesTheScanAndTheChangesForTheService(t *testing.T) {
	fixServer(t)
	if err := os.WriteFile(agentConfPath(), []byte("api: https://api.kiyesi.dev\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath(), []byte("ksv_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runFixCLI(t, "", "fix", "ssh-password", "--yes")
	if code != ExitOK || !strings.Contains(out, "The dashboard shows the new grade within a minute.") {
		t.Fatalf("%d\n%s", code, out)
	}
	entries, _ := os.ReadDir(outboxDir())
	if len(entries) != 1 {
		t.Fatalf("outbox has %d batches", len(entries))
	}
	f, _ := os.Open(filepath.Join(outboxDir(), entries[0].Name()))
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var b send.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 2 || b.Items[0].Kind != "scan" || b.Items[1].Kind != "fixed" {
		t.Fatalf("items = %+v", b.Items)
	}
	if fx := b.Items[1].Fixed; fx.Fix != "ssh-password" || fx.User != "ada" || fx.Done != "SSH password login off" || fx.Undo {
		t.Errorf("fixed = %+v", fx)
	}
	for _, c := range b.Items[0].Report.Checks {
		if c.ID == "ssh" && c.Status != "pass" {
			t.Errorf("the scan sent is from before the fix: %+v", c)
		}
	}
}

func TestFixUndoListsAndPutsBack(t *testing.T) {
	h := fixServer(t)
	if code, out, _ := runFixCLI(t, "", "fix", "undo"); code != ExitOK || !strings.Contains(out, "kiyesi fix has not changed anything on this server.") {
		t.Fatalf("%d %s", code, out)
	}
	if code, _, _ := runFixCLI(t, "", "fix", "--yes"); code != ExitOK {
		t.Fatal("fix failed")
	}
	_, out, _ := runFixCLI(t, "", "fix", "undo")
	if !strings.Contains(out, "SSH password login off") || !strings.Contains(out, "(ada · undo: sudo kiyesi fix undo ") {
		t.Fatalf("list:\n%s", out)
	}
	var id string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SSH password login off") {
			id = strings.Fields(line)[0]
		}
	}
	code, out, errOut := runFixCLI(t, "y\n", "fix", "undo", id)
	if code != ExitOK || !strings.Contains(out, "✓ Undone: SSH password login off") || !strings.Contains(errOut, `Undo "SSH password login off", made by ada`) {
		t.Fatalf("%d\n%s\n%s", code, out, errOut)
	}
	if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
		t.Error("not put back")
	}
	if _, out, _ := runFixCLI(t, "", "fix", "undo"); !strings.Contains(out, "undone ") {
		t.Errorf("not marked undone:\n%s", out)
	}
	if code, _, errOut := runFixCLI(t, "", "fix", "undo", "nope"); code != ExitUsage || !strings.Contains(errOut, "is not a fix id") {
		t.Errorf("%d %q", code, errOut)
	}
}

// The team's home country, as the service last said it, is used when the
// server's own settings name none; the server's own setting wins.
func TestScanUsesTheTeamsHomeCountry(t *testing.T) {
	testSystem(t)
	t.Setenv("KIYESI_STATE", t.TempDir())
	r, _, err := runScan(context.Background(), configFlag, 0, render.ByScan)
	if err != nil || r.Home.Code != "" {
		t.Fatalf("no country anywhere: %q %v", r.Home.Code, err)
	}
	if err := saveTeamHome("DE"); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := runScan(context.Background(), configFlag, 0, render.ByScan); r.Home.Code != "DE" || r.Home.Name != "Germany" {
		t.Fatalf("team's choice: %+v", r.Home)
	}
	if err := os.WriteFile(configFlag, []byte("home_country: ng\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := runScan(context.Background(), configFlag, 0, render.ByScan); r.Home.Code != "NG" {
		t.Fatalf("the server's own setting: %+v", r.Home)
	}
	if err := saveTeamHome(""); err != nil || teamHome() != "" {
		t.Fatalf("cleared: %q %v", teamHome(), err)
	}
}

// After a failed fix the line says "Nothing was changed" only when that is
// true: the fix was put back, or never started.
func TestAFailedFixSaysWhatMayHaveChanged(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"ssh-password", &fix.Failed{Err: errors.New("x")}, "Nothing was changed."},
		{"updates", &fix.Failed{Err: errors.New("x")}, "Nothing was changed."},
		{"updates", &fix.Failed{Err: errors.New("x"), Changed: true}, "Some updates may have installed before it stopped."},
		{"certificates", &fix.Failed{Err: errors.New("x"), Changed: true}, "Some certificates may have been renewed before it stopped."},
		{"docker-cleanup", &fix.Failed{Err: errors.New("x"), Changed: true}, "Some unused images or build cache may have been removed before it stopped."},
		{"firewall", &fix.Failed{Err: errors.New("x; putting it back also failed"), Changed: true}, "Part of it may still be changed."},
	} {
		if got := afterFailure(c.name, c.err); got != c.want {
			t.Errorf("%s %v: %q, want %q", c.name, c.err, got, c.want)
		}
	}
}

// A fix that fails is put back, and says so.
func TestAFixPutBackSaysNothingChanged(t *testing.T) {
	h := fixServer(t)
	h.chmodErr = errors.New("read-only file system")
	code, out, _ := runFixCLI(t, "", "fix", "secret-files", "--yes")
	if code != ExitFindings || !strings.Contains(out, "✗ secret-files: read-only file system. Nothing was changed.") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// The scan offers kiyesi fix only where it would run: not with fix: off,
// and not on a system it does not know. The saved report says the same.
func TestScanOffersKiyesiFixOnlyWhereItRuns(t *testing.T) {
	fixServer(t)
	report := func(out string) string {
		_, path, ok := strings.Cut(out, "Full report with every fix command: ")
		if !ok {
			t.Fatalf("no report path in:\n%s", out)
		}
		data, err := os.ReadFile(strings.TrimSpace(strings.SplitN(path, "\n", 2)[0]))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	_, out, _ := runCLI(t, "scan")
	// ssh-password, login-protection and secret-files.
	if !strings.Contains(out, "Kiyesi can fix 3 things for you: sudo kiyesi fix") || !strings.Contains(report(out), "Fix: sudo kiyesi fix secret-files") {
		t.Fatalf("fix allowed, not offered:\n%s", out)
	}
	if err := os.WriteFile(configFlag, []byte("fix: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ = runCLI(t, "scan")
	if strings.Contains(out, "kiyesi fix") || strings.Contains(report(out), "kiyesi fix") {
		t.Errorf("fix: off, still offered:\n%s\n%s", out, report(out))
	}
	if err := os.WriteFile(configFlag, []byte("fix: on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := newSystem
	newSystem = func(root bool, dir string) *system.System {
		s := base(root, dir)
		s.OS = system.OSInfo{ID: "rocky", Name: "Rocky Linux 9"}
		return s
	}
	_, out, _ = runCLI(t, "scan")
	if strings.Contains(out, "kiyesi fix") || strings.Contains(report(out), "kiyesi fix") {
		t.Errorf("another system, still offered:\n%s\n%s", out, report(out))
	}
}

// Saying no to ssh-password keeps the passwords, so login-protection, planned
// as not needed, runs after all.
func TestLoginProtectionRunsWhenPasswordsStayOn(t *testing.T) {
	fixServer(t)
	code, out, _ := runFixCLI(t, "choose\nn\ny\nn\n", "fix")
	if code != ExitOK || strings.Contains(out, "✓ SSH password login off") || !strings.Contains(out, "✓ fail2ban on") || strings.Contains(out, "Not needed") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// A grade that does not move after a real fix is not called a clean-up:
// the line names what is still there.
func TestAGradeThatDidNotMoveSaysWhy(t *testing.T) {
	ssh := &planned{findings: []scan.Finding{{Severity: "warning", Sentence: "SSH allows password login"}}}
	clean := &planned{findings: []scan.Finding{{Severity: "info", Sentence: "Docker keeps 2 GB"}}}
	before := scan.Report{Checks: []scan.CheckResult{{Findings: []scan.Finding{{Severity: "warning", Sentence: "SSH allows password login"}}}}}
	after := scan.Report{Checks: []scan.CheckResult{{Findings: []scan.Finding{
		{Severity: "warning", Sentence: "SSH allows password login"},
		{Severity: "warning", Sentence: "Port 8080 is open on a public address"},
	}}}}
	if onlyCleanUps([]*planned{ssh, clean}) || !onlyCleanUps([]*planned{clean}) {
		t.Error("onlyCleanUps")
	}
	if got := notBetter(before, after, []*planned{ssh}); got != "Still there: SSH allows password login. New: Port 8080 is open on a public address." {
		t.Errorf("got %q", got)
	}
}
