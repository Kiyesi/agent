package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"hash/fnv"
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
	oldDir, oldRoot, oldTerm := fixStoreDir, fixAsRoot, fixTerminal
	t.Cleanup(func() { fixStoreDir, fixAsRoot, fixTerminal = oldDir, oldRoot, oldTerm })
	fixStoreDir = t.TempDir()
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

// kiyesi fix undo lists the changes kiyesi fix made before 0.40.0 and, for
// one, prints the commands that put it back, for a person to review and
// run: it changes nothing, with --yes too.
func TestFixUndoPrintsTheCommandsAndChangesNothing(t *testing.T) {
	h := fixServer(t)
	if code, out, _ := runFixCLI(t, "", "fix", "undo"); code != ExitOK || !strings.Contains(out, "kiyesi fix has not changed anything on this server.") {
		t.Fatalf("%d %s", code, out)
	}
	// A record as kiyesi fix kept it before 0.40.0: a file it added, a file
	// it rewrote, a mode it changed, a key it took out, and SSH reloaded.
	rec := fix.Record{ID: "7f3a", Fix: "ssh-password", Done: "SSH password login off", User: "ada", At: time.Now(), CanUndo: true,
		Files: []fix.Saved{
			{Path: "/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"},
			{Path: "/etc/fail2ban/jail.d/kiyesi.conf", Existed: true, Mode: 0o644, Content: []byte("[sshd]\nenabled = false\n")},
			{Path: "/srv/app/.env", Existed: true, Mode: 0o644, ModeOnly: true},
		},
		Keys: []fix.KeyLines{{User: "ada", Path: "/home/ada/.ssh/authorized_keys", Lines: []string{"ssh-ed25519 AAAAC3Nza old@laptop"}}},
		Then: [][]string{{"systemctl", "reload", "ssh"}},
	}
	data, _ := json.Marshal(rec)
	if err := os.MkdirAll(filepath.Join(fixStoreDir, rec.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixStoreDir, rec.ID, "record.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := runFixCLI(t, "", "fix", "undo")
	if !strings.Contains(out, "SSH password login off") || !strings.Contains(out, "how to put it back: sudo kiyesi fix undo 7f3a") {
		t.Fatalf("list:\n%s", out)
	}
	files := len(h.files)
	code, out, errOut := runFixCLI(t, "", "fix", "undo", "7f3a", "--yes")
	if code != ExitOK {
		t.Fatalf("%d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Kiyesi changes nothing on this server. It only suggests: you review each command and run it yourself.",
		`To put back "SSH password login off", made by ada`,
		"First: Check /srv/app/.env is still the file you expect",
		"sudo chmod 0644 /srv/app/.env",
		"sudo tee /etc/fail2ban/jail.d/kiyesi.conf >/dev/null <<'KIYESI_EOF'\n    [sshd]\n    enabled = false\n    KIYESI_EOF",
		"sudo rm -f /etc/ssh/sshd_config.d/00-kiyesi-no-password.conf",
		"echo 'ssh-ed25519 AAAAC3Nza old@laptop' | sudo tee -a /home/ada/.ssh/authorized_keys >/dev/null",
		"sudo systemctl reload ssh",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if len(h.files) != files || len(h.ran) != 0 {
		t.Errorf("something changed or ran: %v", h.ran)
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

// kiyesi fix changes nothing and runs nothing: it scans and lists each
// finding with its commands, for the person to review and run, with --yes
// and --dry-run too, and as JSON.
func TestFixOnlySuggests(t *testing.T) {
	h := fixServer(t)
	files := len(h.files)
	for _, args := range [][]string{{"fix"}, {"fix", "--yes"}, {"fix", "--dry-run"}} {
		code, out, errOut := runFixCLI(t, "", args...)
		if code != ExitOK {
			t.Fatalf("%v: %d %q %q", args, code, out, errOut)
		}
		for _, want := range []string{
			"Kiyesi changes nothing on this server. It only suggests: you review each command and run it yourself.",
			"What to do, for you to review and run yourself:",
			"SSH allows password login",
			"Read each command before you run it. It changes your server, and you are the one who runs it.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%v: missing %q in:\n%s", args, want, out)
			}
		}
		if strings.Contains(out, "sudo kiyesi fix ") {
			t.Errorf("%v offered kiyesi fix:\n%s", args, out)
		}
	}
	if len(h.files) != files || len(h.ran) != 0 {
		t.Errorf("something changed or ran: files %d→%d, ran %v", files, len(h.files), h.ran)
	}
	code, out, _ := runFixCLI(t, "", "fix", "--json")
	var got struct {
		Changed     bool `json:"changed"`
		Suggestions []struct{ Check, Severity, Sentence, Commands string }
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != ExitOK || got.Changed || len(got.Suggestions) == 0 {
		t.Errorf("json: %d %v %+v\n%s", code, err, got, out)
	}
}

// A fix's name narrows the list to the checks it covers; an unknown name,
// or running it without sudo, says so.
func TestFixNamesAndRefusals(t *testing.T) {
	fixServer(t)
	code, out, _ := runFixCLI(t, "", "fix", "firewall")
	if code != ExitOK || strings.Contains(out, "SSH allows password login") {
		t.Errorf("firewall only: %d\n%s", code, out)
	}
	if code, _, errOut := runFixCLI(t, "", "fix", "nope"); code != ExitUsage || !strings.Contains(errOut, `There is no fix called "nope"`) {
		t.Errorf("unknown: %d %q", code, errOut)
	}
	fixAsRoot = func() bool { return false }
	if code, _, errOut := runFixCLI(t, "", "fix"); code != ExitNoAccess || !strings.Contains(errOut, "Run it with sudo") {
		t.Errorf("not root: %d %q", code, errOut)
	}
}
