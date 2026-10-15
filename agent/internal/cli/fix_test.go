package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/send"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// cliHost is the server kiyesi fix changes in these tests. The scan reads
// the same files, so checking again after a fix sees what it changed.
type cliHost struct {
	files map[string][]byte
	modes map[string]fs.FileMode
	ran   []string
}

type cliInfo struct{ mode fs.FileMode }

func (i cliInfo) Name() string       { return "" }
func (i cliInfo) Size() int64        { return 0 }
func (i cliInfo) Mode() fs.FileMode  { return i.mode }
func (i cliInfo) ModTime() time.Time { return time.Time{} }
func (i cliInfo) IsDir() bool        { return false }
func (i cliInfo) Sys() any           { return nil }

func (h *cliHost) ReadFile(p string) ([]byte, error) {
	if d, ok := h.files[p]; ok {
		return d, nil
	}
	return nil, fs.ErrNotExist
}
func (h *cliHost) Lstat(p string) (fs.FileInfo, error) {
	if _, ok := h.files[p]; !ok {
		return nil, fs.ErrNotExist
	}
	return cliInfo{h.modes[p]}, nil
}
func (h *cliHost) WriteFile(p string, d []byte, m fs.FileMode) error {
	h.files[p], h.modes[p] = d, m
	return nil
}
func (h *cliHost) Remove(p string) error { delete(h.files, p); return nil }
func (h *cliHost) Chmod(p string, m fs.FileMode) error {
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
	case "systemctl is-active ssh":
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
		"Kiyesi can fix 2 things for you:",
		"1. SSH allows password login (ssh-password)",
		"Turns SSH password login off. ada has an SSH key here, so you stay in.",
		// Not needed once passwords are off.
		"Not needed: with SSH password login off, there is no password to guess.",
		"/srv/app/.env holds secrets and every user on this server can read it (secret-files)",
		"✓ SSH password login off  (undo: sudo kiyesi fix undo ",
		"✓ Secret files closed to other users  (undo: sudo kiyesi fix undo ",
		"Checking again…",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "Fix all 2? [y/N/choose]") {
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
	code, out, _ := runFixCLI(t, "choose\nn\ny\n", "fix")
	if code != ExitOK || strings.Contains(out, "✓ SSH password login off") || !strings.Contains(out, "✓ Secret files closed") {
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
	if code, _, errOut := runFixCLI(t, "", "fix", "everything"); code != ExitUsage || !strings.Contains(errOut, `There is no fix called "everything". The fixes are: certificates, firewall,`) {
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
