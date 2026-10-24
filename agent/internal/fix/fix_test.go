package fix

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

// fakeHost is a server in memory: files, and programs that answer as the
// test says. Every command run is kept, so a test can see the order.
type fakeHost struct {
	files    map[string][]byte
	modes    map[string]fs.FileMode
	links    map[string]bool
	programs map[string]bool
	ran      []string
	answer   func(cmd string) (string, error)
}

func newHost() *fakeHost {
	return &fakeHost{
		files: map[string][]byte{
			"/etc/passwd":                    []byte("root:x:0:0:root:/root:/bin/bash\nada:x:1000:1000::/home/ada:/bin/bash\n"),
			"/etc/ssh/sshd_config":           []byte("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n"),
			"/home/ada/.ssh/authorized_keys": []byte("ssh-ed25519 AAAA ada@laptop\n"),
			"/etc/ufw/ufw.conf":              []byte("ENABLED=no\n"),
			"/etc/ufw/user.rules":            []byte("# rules\n"),
			"/etc/ufw/user6.rules":           []byte("# rules6\n"),
		},
		modes:    map[string]fs.FileMode{},
		links:    map[string]bool{},
		programs: map[string]bool{"sshd": true, "systemctl": true, "ufw": true, "apt-get": true, "certbot": true},
	}
}

type info struct {
	name string
	mode fs.FileMode
}

func (i info) Name() string       { return i.name }
func (i info) Size() int64        { return 0 }
func (i info) Mode() fs.FileMode  { return i.mode }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.mode.IsDir() }

// Sys gives each path its own inode, owned by root, as a real file has.
func (i info) Sys() any { return &syscall.Stat_t{Ino: inodeOf(i.name)} }

func inodeOf(p string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(p))
	return h.Sum64()
}

func (h *fakeHost) ReadFile(p string) ([]byte, error) {
	d, ok := h.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return d, nil
}

func (h *fakeHost) Lstat(p string) (fs.FileInfo, error) {
	if h.links[p] {
		return info{p, fs.ModeSymlink | 0o777}, nil
	}
	if _, ok := h.files[p]; !ok {
		for f := range h.files {
			if strings.HasPrefix(f, p+"/") {
				return info{p, fs.ModeDir | 0o755}, nil
			}
		}
		return nil, fs.ErrNotExist
	}
	m, ok := h.modes[p]
	if !ok {
		m = 0o644
	}
	return info{p, m}, nil
}

func (h *fakeHost) WriteFile(p string, d []byte, perm fs.FileMode) error {
	h.files[p] = append([]byte(nil), d...)
	h.modes[p] = perm
	return nil
}

func (h *fakeHost) Remove(p string) error {
	delete(h.files, p)
	delete(h.modes, p)
	return nil
}

func (h *fakeHost) ChmodFile(p string, want FileID, perm fs.FileMode) error {
	if _, ok := h.files[p]; !ok || h.links[p] || want.Ino != inodeOf(p) {
		return fs.ErrNotExist
	}
	h.modes[p] = perm
	return nil
}

func (h *fakeHost) Has(name string) bool { return h.programs[name] }

func (h *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	h.ran = append(h.ran, cmd)
	if h.answer != nil {
		out, err := h.answer(cmd)
		return []byte(out), err
	}
	return nil, nil
}

func (h *fakeHost) didRun(cmd string) bool { return slices.Contains(h.ran, cmd) }

// sshd answers as a real one would for the files in the fake host.
func (h *fakeHost) sshdAnswers() {
	h.answer = func(cmd string) (string, error) {
		switch cmd {
		case "systemctl is-active ssh":
			return "active\n", nil
		case "sshd -T":
			out := "port 22\n"
			if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
				out += "passwordauthentication no\n"
			} else {
				out += "passwordauthentication yes\n"
			}
			if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-root.conf"]; ok {
				out += "permitrootlogin no\n"
			} else {
				out += "permitrootlogin yes\n"
			}
			return out, nil
		}
		return "", nil
	}
}

func store(t *testing.T) *Store { return &Store{Dir: t.TempDir()} }

func input(user string) Input {
	return Input{Cfg: config.Default(), User: user, Planned: map[string]bool{}}
}

func TestPasswordLoginOffAndBack(t *testing.T) {
	h := newHost()
	h.sshdAnswers()
	f := sshPassword{}
	p := f.Plan(context.Background(), h, input("ada"))
	if p.Refuse != "" || !p.Undoable || !strings.Contains(p.Say, "ada has an SSH key here, so you stay in") {
		t.Fatalf("plan = %+v", p)
	}
	s := store(t)
	rec, err := Run(context.Background(), h, s, f, input("ada"), p)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"])
	if !strings.Contains(conf, "PasswordAuthentication no") || !strings.Contains(conf, "KbdInteractiveAuthentication no") {
		t.Fatalf("drop-in = %q", conf)
	}
	// Checked before SSH reloads, and reloaded, never restarted.
	i, j := slices.Index(h.ran, "sshd -t"), slices.Index(h.ran, "systemctl reload ssh")
	if i < 0 || j < i || slices.ContainsFunc(h.ran, func(c string) bool { return strings.Contains(c, "restart") }) {
		t.Fatalf("ran %v", h.ran)
	}
	got, err := s.Get(rec.ID)
	if err != nil || !got.CanUndo {
		t.Fatalf("record %+v %v", got, err)
	}
	h.ran = nil
	if err := s.Undo(context.Background(), h, got); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
		t.Fatal("the drop-in is still there after undo")
	}
	if !h.didRun("systemctl reload ssh") {
		t.Fatalf("undo did not reload SSH: %v", h.ran)
	}
	again, _ := s.Get(rec.ID)
	if again.UndoneAt == nil {
		t.Fatal("not marked undone")
	}
	if err := s.Undo(context.Background(), h, again); err == nil || !strings.Contains(err.Error(), "undone already") {
		t.Fatalf("second undo: %v", err)
	}
}

func TestPasswordLoginNeedsAKey(t *testing.T) {
	h := newHost()
	delete(h.files, "/home/ada/.ssh/authorized_keys")
	p := sshPassword{}.Plan(context.Background(), h, input("ada"))
	if !strings.Contains(p.Refuse, "ada has no SSH key on this server") || !strings.Contains(p.Refuse, "ssh-copy-id ada@") {
		t.Fatalf("plan = %+v", p)
	}
	// Comments and blank lines are not keys.
	h.files["/home/ada/.ssh/authorized_keys"] = []byte("# none yet\n\n")
	if p := (sshPassword{}).Plan(context.Background(), h, input("ada")); p.Refuse == "" {
		t.Fatal("a file with no keys was taken as a key")
	}
}

func TestSSHLeftAloneWithoutTheIncludeLine(t *testing.T) {
	h := newHost()
	h.files["/etc/ssh/sshd_config"] = []byte("PasswordAuthentication yes\n")
	if p := (sshPassword{}).Plan(context.Background(), h, input("ada")); !strings.Contains(p.Refuse, "does not read the files in /etc/ssh/sshd_config.d") {
		t.Fatalf("plan = %+v", p)
	}
	// An Include after a Match block applies to some logins only.
	h.files["/etc/ssh/sshd_config"] = []byte("Match User git\n  X11Forwarding no\nInclude /etc/ssh/sshd_config.d/*.conf\n")
	if p := (sshPassword{}).Plan(context.Background(), h, input("ada")); p.Refuse == "" {
		t.Fatal("an Include inside a Match block was trusted")
	}
	h.files["/etc/ssh/sshd_config"] = []byte("include sshd_config.d/*.conf\n")
	if p := (sshPassword{}).Plan(context.Background(), h, input("ada")); p.Refuse != "" {
		t.Fatalf("a relative Include was refused: %+v", p)
	}
}

func TestSSHRefusedSettingIsPutBack(t *testing.T) {
	h := newHost()
	h.answer = func(cmd string) (string, error) {
		if cmd == "sshd -t" {
			return "", errors.New("sshd -t failed: bad option")
		}
		return "", nil
	}
	s := store(t)
	_, err := Run(context.Background(), h, s, sshPassword{}, input("ada"), Plan{Done: "x", Undoable: true})
	if err == nil || !strings.Contains(err.Error(), "SSH refused the new setting") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
		t.Fatal("the refused file was left behind")
	}
	if h.didRun("systemctl reload ssh") {
		t.Fatal("SSH was reloaded with a setting it refused")
	}
	if recs, _ := s.List(); len(recs) != 0 {
		t.Fatalf("a failed fix left a record: %+v", recs)
	}
}

func TestSSHSettingThatDoesNotTakeIsPutBack(t *testing.T) {
	h := newHost()
	// sshd_config sets it first, so the drop-in loses.
	h.answer = func(cmd string) (string, error) {
		switch cmd {
		case "systemctl is-active ssh":
			return "active", nil
		case "sshd -T":
			return "passwordauthentication yes\n", nil
		}
		return "", nil
	}
	_, err := Run(context.Background(), h, store(t), sshPassword{}, input("ada"), Plan{Done: "x", Undoable: true})
	if err == nil || !strings.Contains(err.Error(), "a setting earlier in /etc/ssh/sshd_config wins") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"]; ok {
		t.Fatal("left behind")
	}
	// Reloaded once for the change and once more after putting it back.
	n := 0
	for _, c := range h.ran {
		if c == "systemctl reload ssh" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("reloads = %d: %v", n, h.ran)
	}
}

func TestRootLoginNeedsAnotherWayIn(t *testing.T) {
	h := newHost()
	if p := (sshRoot{}).Plan(context.Background(), h, input("root")); !strings.Contains(p.Refuse, "You are signed in as root") {
		t.Fatalf("plan as root = %+v", p)
	}
	delete(h.files, "/home/ada/.ssh/authorized_keys")
	if p := (sshRoot{}).Plan(context.Background(), h, input("ada")); !strings.Contains(p.Refuse, "ada has no SSH key") {
		t.Fatalf("plan without key = %+v", p)
	}
	h = newHost()
	h.sshdAnswers()
	p := sshRoot{}.Plan(context.Background(), h, input("ada"))
	if p.Refuse != "" || !strings.Contains(p.Say, "You sign in as ada") {
		t.Fatalf("plan = %+v", p)
	}
	if _, err := Run(context.Background(), h, store(t), sshRoot{}, input("ada"), p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h.files["/etc/ssh/sshd_config.d/00-kiyesi-no-root.conf"]), "PermitRootLogin no") {
		t.Fatal("no drop-in")
	}
}

func TestFirewallKeepsSSHOpenAndSaysWhatCloses(t *testing.T) {
	h := newHost()
	h.answer = func(cmd string) (string, error) {
		switch cmd {
		case "sshd -T":
			return "port 2222\n", nil
		case "ufw status":
			return "Status: active\n", nil
		}
		return "", nil
	}
	in := input("ada")
	in.Public = []int{80, 443, 2222, 6379}
	f := firewall{}
	p := f.Plan(context.Background(), h, in)
	if !strings.Contains(p.Say, "open only to: 22, 80, 443, SSH (2222)") {
		t.Fatalf("say = %q", p.Say)
	}
	if !p.Confirm || !strings.Contains(p.Warn[0], "will be closed: 6379") {
		t.Fatalf("warn = %+v", p)
	}
	// A port Docker publishes is not closed by ufw, so it is not listed as closing.
	withDocker := in
	withDocker.Public, withDocker.Docker = []int{80, 443, 2222, 6379, 8080}, []int{8080}
	if dp := f.Plan(context.Background(), h, withDocker); !strings.Contains(dp.Warn[0], "will be closed: 6379.") {
		t.Fatalf("docker's port listed as closing: %+v", dp.Warn)
	}
	withDocker.Public = []int{80, 443, 2222, 8080}
	if dp := f.Plan(context.Background(), h, withDocker); dp.Confirm || strings.Contains(strings.Join(dp.Warn, " "), "will be closed") {
		t.Fatalf("only docker's port, still closing: %+v", dp)
	}
	s := store(t)
	rec, err := Run(context.Background(), h, s, f, in, p)
	if err != nil {
		t.Fatal(err)
	}
	// SSH's real port is allowed before the firewall starts.
	allow, enable := slices.Index(h.ran, "ufw allow 2222/tcp"), slices.Index(h.ran, "ufw --force enable")
	if allow < 0 || enable < allow {
		t.Fatalf("ran %v", h.ran)
	}
	h.files["/etc/ufw/ufw.conf"] = []byte("ENABLED=yes\n")
	h.files["/etc/ufw/user.rules"] = []byte("# rules with 2222\n")
	h.ran = nil
	got, _ := s.Get(rec.ID)
	if err := s.Undo(context.Background(), h, got); err != nil {
		t.Fatal(err)
	}
	if string(h.files["/etc/ufw/ufw.conf"]) != "ENABLED=no\n" || string(h.files["/etc/ufw/user.rules"]) != "# rules\n" {
		t.Fatalf("not restored: %q %q", h.files["/etc/ufw/ufw.conf"], h.files["/etc/ufw/user.rules"])
	}
	if !h.didRun("ufw --force disable") {
		t.Fatalf("undo ran %v", h.ran)
	}
}

func TestFirewallWithNothingToClose(t *testing.T) {
	h := newHost()
	in := input("ada")
	in.Public = []int{22, 443}
	if p := (firewall{}).Plan(context.Background(), h, in); p.Confirm || !strings.HasPrefix(p.Say, "Turns the firewall on, open only to: SSH (22), 80, 443.") {
		t.Fatalf("plan = %+v", p)
	}
	h.programs["ufw"] = false
	if p := (firewall{}).Plan(context.Background(), h, in); !strings.HasPrefix(p.Say, "Installs ufw and turns") {
		t.Fatalf("say = %q", p.Say)
	}
}

func TestFirewallThatDoesNotStartIsPutBack(t *testing.T) {
	h := newHost()
	h.programs["ufw"] = false
	h.answer = func(cmd string) (string, error) {
		if cmd == "apt-get install -y -q ufw" {
			h.programs["ufw"] = true
		}
		if cmd == "ufw status" {
			return "Status: inactive\n", nil
		}
		return "", nil
	}
	_, err := Run(context.Background(), h, store(t), firewall{}, input("ada"), Plan{Done: "x", Undoable: true})
	if err == nil || !strings.Contains(err.Error(), "ufw did not turn on") {
		t.Fatalf("err = %v", err)
	}
	// Off again, then what this fix installed is removed.
	d, r := slices.Index(h.ran, "ufw --force disable"), slices.Index(h.ran, "apt-get remove -y -q ufw")
	if d < 0 || r < d {
		t.Fatalf("ran %v", h.ran)
	}
}

func TestLoginProtection(t *testing.T) {
	h := newHost()
	in := input("ada")
	in.Planned["ssh-password"] = true
	// Planned with ssh-password, it waits to see whether that one works.
	if p := (loginProtection{}).Plan(context.Background(), h, in); p.Skip != "" || p.Unless != "ssh-password" || !strings.Contains(p.UnlessSkip, "Not needed") || !strings.Contains(p.Say, "Skipped if ssh-password turns password login off first.") {
		t.Fatalf("plan = %+v", p)
	}
	h.answer = func(cmd string) (string, error) {
		if cmd == "systemctl is-active fail2ban" {
			return "active", nil
		}
		return "", nil
	}
	p := loginProtection{}.Plan(context.Background(), h, input("ada"))
	if !strings.HasPrefix(p.Say, "Installs fail2ban") {
		t.Fatalf("plan = %+v", p)
	}
	s := store(t)
	rec, err := Run(context.Background(), h, s, loginProtection{}, input("ada"), p)
	if err != nil {
		t.Fatal(err)
	}
	// No auth.log here, so fail2ban reads the journal.
	if !h.didRun("apt-get install -y -q fail2ban python3-systemd") || !strings.Contains(string(h.files["/etc/fail2ban/jail.d/kiyesi.conf"]), "backend = systemd") {
		t.Fatalf("ran %v", h.ran)
	}
	h.ran = nil
	got, _ := s.Get(rec.ID)
	if err := s.Undo(context.Background(), h, got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.ran, []string{"systemctl disable --now fail2ban", "apt-get remove -y -q fail2ban"}) {
		t.Fatalf("undo ran %v", h.ran)
	}
	if _, ok := h.files["/etc/fail2ban/jail.d/kiyesi.conf"]; ok {
		t.Fatal("the jail file is still there")
	}
}

func TestLoginProtectionStartsAnInstalledOne(t *testing.T) {
	h := newHost()
	h.files[fail2banClient] = nil
	h.files["/var/log/auth.log"] = nil
	h.answer = func(cmd string) (string, error) {
		if cmd == "systemctl is-active fail2ban" {
			return "active", nil
		}
		return "", nil
	}
	p := loginProtection{}.Plan(context.Background(), h, input("ada"))
	if !strings.HasPrefix(p.Say, "Starts fail2ban") {
		t.Fatalf("plan = %+v", p)
	}
	if _, err := Run(context.Background(), h, store(t), loginProtection{}, input("ada"), p); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(h.ran, func(c string) bool { return strings.HasPrefix(c, "apt-get") }) {
		t.Fatalf("installed again: %v", h.ran)
	}
}

func TestSecretFilesKeepOwnerAndGroupAndNeverCopyTheSecret(t *testing.T) {
	h := newHost()
	h.files["/srv/app/.env"] = []byte("DB_PASSWORD=correct-horse-battery")
	h.modes["/srv/app/.env"] = 0o664
	h.files["/srv/other/.env"] = []byte("x")
	h.links["/srv/link/.env"] = true
	in := input("ada")
	in.Findings = []checks.Finding{
		checks.Found("world-readable", map[string]string{"path": "/srv/app/.env"}),
		checks.Found("world-readable", map[string]string{"path": "/srv/link/.env"}),
	}
	f := secretFile{}
	p := f.Plan(context.Background(), h, in)
	if !strings.Contains(p.Say, "Makes 1 file unreadable to other users") || !strings.Contains(p.Warn[0], "/srv/link/.env") {
		t.Fatalf("plan = %+v", p)
	}
	s := store(t)
	rec, err := Run(context.Background(), h, s, f, in, p)
	if err != nil {
		t.Fatal(err)
	}
	if h.modes["/srv/app/.env"] != 0o660 {
		t.Fatalf("mode = %o", h.modes["/srv/app/.env"])
	}
	got, _ := s.Get(rec.ID)
	for _, f := range got.Files {
		if len(f.Content) > 0 {
			t.Fatalf("the record copied the file's content: %+v", f)
		}
	}
	if err := s.Undo(context.Background(), h, got); err != nil {
		t.Fatal(err)
	}
	if h.modes["/srv/app/.env"] != 0o664 {
		t.Fatalf("mode after undo = %o", h.modes["/srv/app/.env"])
	}
}

func TestUpdatesSayTheyCannotBeUndoneAndNeverRestart(t *testing.T) {
	h := newHost()
	in := input("ada")
	in.Findings = []checks.Finding{checks.Found("waiting", map[string]string{"count": "12"})}
	p := updates{}.Plan(context.Background(), h, in)
	if p.Undoable || !strings.Contains(p.Say, "(12 for security)") || !strings.Contains(p.Say, "cannot be undone") {
		t.Fatalf("plan = %+v", p)
	}
	h.files["/var/run/reboot-required"] = nil
	s := store(t)
	rec, err := Run(context.Background(), h, s, updates{}, in, p)
	if err != nil {
		t.Fatal(err)
	}
	if !h.didRun("apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade --with-new-pkgs") {
		t.Fatalf("ran %v", h.ran)
	}
	if slices.ContainsFunc(h.ran, func(c string) bool { return strings.Contains(c, "reboot") }) {
		t.Fatalf("restarted: %v", h.ran)
	}
	if !strings.Contains(rec.Done, "Restart the server when it suits you: sudo reboot") {
		t.Fatalf("done = %q", rec.Done)
	}
	got, _ := s.Get(rec.ID)
	if err := s.Undo(context.Background(), h, got); err == nil || !strings.Contains(err.Error(), "cannot be undone") {
		t.Fatalf("undo: %v", err)
	}
}

func TestUpdatesWhenAptIsBusy(t *testing.T) {
	h := newHost()
	h.answer = func(cmd string) (string, error) {
		return "", errors.New("E: Could not get lock /var/lib/dpkg/lock-frontend")
	}
	_, err := Run(context.Background(), h, store(t), updates{}, input("ada"), Plan{Done: "x"})
	if err == nil || !strings.Contains(err.Error(), "another update is running") {
		t.Fatalf("err = %v", err)
	}
}

func TestCertificates(t *testing.T) {
	h := newHost()
	in := input("ada")
	in.Findings = []checks.Finding{
		checks.Found("expiring", map[string]string{"host": "shop.example.com"}),
		checks.Found("expired", map[string]string{"host": "shop.example.com"}),
	}
	p := certificates{}.Plan(context.Background(), h, in)
	if !strings.Contains(p.Say, "shop.example.com.") || strings.Count(p.Say, "shop.example.com") != 1 {
		t.Fatalf("say = %q", p.Say)
	}
	if _, err := Run(context.Background(), h, store(t), certificates{}, in, p); err != nil || !h.didRun("certbot renew --non-interactive") {
		t.Fatalf("%v %v", err, h.ran)
	}
	h.programs["certbot"] = false
	if p := (certificates{}).Plan(context.Background(), h, in); p.Refuse == "" {
		t.Fatal("planned without certbot")
	}
}

// A certificate Caddy looks after has a variant fix in the pack, which needs a person.
func TestOnlyTheUsualFixIsAutomatic(t *testing.T) {
	if For("certificates", checks.Finding{Key: "expiring", Variant: "caddy"}) != nil {
		t.Fatal("a variant was given to kiyesi fix")
	}
	if x := For("certificates", checks.Finding{Key: "expiring"}); x == nil || x.Name() != "certificates" {
		t.Fatal("the usual certificate finding has no fix")
	}
}

// The pack's auto lines, which the report and the dashboard show, name
// exactly the fixes that answer each finding.
func TestThePackNamesTheFixes(t *testing.T) {
	pack, err := packs.English()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range pack.Checks {
		for key, f := range c.Findings {
			x := For(c.ID, checks.Finding{Key: key})
			switch {
			case x == nil && f.Auto != "":
				t.Errorf("%s/%s says auto: %s, but no fix answers it", c.ID, key, f.Auto)
			case x != nil && f.Auto != x.Name():
				t.Errorf("%s/%s is fixed by %s, but the pack says auto: %q", c.ID, key, x.Name(), f.Auto)
			case x != nil:
				seen[x.Name()] = true
			}
		}
	}
	for _, x := range All() {
		if !seen[x.Name()] {
			t.Errorf("fix %s answers no finding in the pack", x.Name())
		}
	}
}

func TestStoreIDs(t *testing.T) {
	s := store(t)
	for _, bad := range []string{"", "7f3", "../etc", "7F3A", "zzzz"} {
		if _, err := s.Get(bad); err == nil {
			t.Errorf("%q was accepted as an id", bad)
		}
	}
	if _, err := s.Get("0000"); err == nil || !strings.Contains(err.Error(), "no fix 0000") {
		t.Fatalf("err = %v", err)
	}
	ids := map[string]bool{}
	for i := range 30 {
		r, err := s.Begin("x", fmt.Sprint(i), "ada", true)
		if err != nil {
			t.Fatal(err)
		}
		if ids[r.ID] {
			t.Fatalf("id %s twice", r.ID)
		}
		ids[r.ID] = true
	}
}

func TestDockerCleanupNeverTouchesContainersOrVolumes(t *testing.T) {
	h := newHost()
	h.programs["docker"] = true
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "docker image prune") {
			return "Deleted Images:\nuntagged: shop:1.3\n\nTotal reclaimed space: 3.1GB\n", nil
		}
		// Newer Docker says only "Total:" for build cache.
		return "ID\tRECLAIMABLE\tSIZE\nab12\ttrue\t1.1GB\nTotal:\t1.1GB\n", nil
	}
	in := input("ada")
	in.Findings = []checks.Finding{checks.Found("docker-waste", map[string]string{"size": "4.2 GB"})}
	p := dockerCleanup{}.Plan(context.Background(), h, in)
	if p.Undoable || !strings.Contains(p.Say, "Removes Docker images no container uses that were created over a week ago, and build cache over a week old. Of the 4.2 GB Docker keeps unused now, only that part goes") || strings.Contains(p.Say, "newer stays") || !strings.Contains(p.Say, "cannot be undone") {
		t.Fatalf("plan = %+v", p)
	}
	rec, err := Run(context.Background(), h, store(t), dockerCleanup{}, in, p)
	if err != nil {
		t.Fatal(err)
	}
	if !h.didRun("docker image prune -a -f --filter until=168h") || !h.didRun("docker builder prune -f --filter until=168h") {
		t.Fatalf("ran %v", h.ran)
	}
	for _, c := range h.ran {
		if strings.Contains(c, "volume") || strings.Contains(c, "container") || strings.Contains(c, "system prune") {
			t.Fatalf("ran %q", c)
		}
	}
	if rec.Done != "Unused Docker images and build cache removed: 3.1GB of images and 1.1GB of build cache freed" {
		t.Fatalf("done = %q", rec.Done)
	}
	// Nothing old enough: it says so, rather than promising space it did not free.
	h.answer = func(string) (string, error) { return "Total reclaimed space: 0B\n", nil }
	if rec, err := Run(context.Background(), h, store(t), dockerCleanup{}, in, p); err != nil || rec.Done != "No unused image was created over a week ago and no build cache was over a week old, so nothing was removed" {
		t.Fatalf("done = %q, %v", rec.Done, err)
	}
	delete(h.programs, "docker")
	if p := (dockerCleanup{}).Plan(context.Background(), h, in); p.Refuse == "" {
		t.Fatal("planned without docker")
	}
}

// testFix is a fix whose Apply does what the test says.
type testFix struct{ apply func(c *Changes) error }

func (testFix) Name() string                                                 { return "test" }
func (testFix) Targets() []Target                                            { return nil }
func (testFix) Plan(context.Context, Host, Input) Plan                       { return Plan{} }
func (f testFix) Apply(_ context.Context, _ Host, _ Input, c *Changes) error { return f.apply(c) }

// A failed fix says whether the server may still be changed: not when it
// was put back, but a fix that cannot be undone may have done part of its
// work, and a fix whose putting back failed may be half done.
func TestFailedSaysWhetherAnythingChanged(t *testing.T) {
	boom := testFix{apply: func(*Changes) error { return errors.New("boom") }}
	var f *Failed
	_, err := Run(context.Background(), newHost(), store(t), boom, input("ada"), Plan{Done: "x", Undoable: true})
	if !errors.As(err, &f) || f.Changed {
		t.Errorf("undoable, put back: %#v", err)
	}
	_, err = Run(context.Background(), newHost(), store(t), boom, input("ada"), Plan{Done: "x"})
	if !errors.As(err, &f) || !f.Changed {
		t.Errorf("cannot be undone, stopped partway: %#v", err)
	}
	h := newHost()
	h.answer = func(cmd string) (string, error) {
		if cmd == "systemctl reload ssh" {
			return "", errors.New("reload failed")
		}
		return "", nil
	}
	half := testFix{apply: func(c *Changes) error {
		if err := c.Write("/etc/ssh/sshd_config.d/x.conf", []byte("x"), 0o644); err != nil {
			return err
		}
		if err := c.Then("systemctl", "reload", "ssh"); err != nil {
			return err
		}
		return errors.New("boom")
	}}
	_, err = Run(context.Background(), h, store(t), half, input("ada"), Plan{Done: "x", Undoable: true})
	if !errors.As(err, &f) || !f.Changed || !strings.Contains(err.Error(), "putting it back also failed") {
		t.Errorf("putting back failed: %#v", err)
	}
}

// A fix that worked but whose undo record could not be saved is done: the
// record comes back with a NotKept, not a failure.
func TestFixDoneButRecordNotSaved(t *testing.T) {
	s := store(t)
	gone := testFix{apply: func(c *Changes) error {
		// The record's folder becomes a file, so the record cannot be written.
		dir := s.dirOf(c.rec.ID)
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		return os.WriteFile(dir, []byte("x"), 0o600)
	}}
	rec, err := Run(context.Background(), newHost(), s, gone, input("ada"), Plan{Done: "Done it", Undoable: true})
	var nk *NotKept
	var f *Failed
	if rec == nil || rec.Done != "Done it" || !errors.As(err, &nk) || errors.As(err, &f) {
		t.Fatalf("rec %+v, err %#v", rec, err)
	}
	if !strings.Contains(err.Error(), "kiyesi fix undo cannot put it back") {
		t.Errorf("err = %v", err)
	}
}

// Signed in as root, the refusal says what is already true: with passwords
// off root can only use its key; with them on, that fix comes first.
func TestRootRefusalSaysWhatIsAlreadyTrue(t *testing.T) {
	h := newHost()
	in := input("root")
	in.SSH.PasswordLogin = false
	if p := (sshRoot{}).Plan(context.Background(), h, in); !strings.Contains(p.Refuse, "Password login is already off, so root can sign in only with its key") {
		t.Errorf("passwords off: %q", p.Refuse)
	}
	in.SSH.PasswordLogin = true
	p := (sshRoot{}).Plan(context.Background(), h, in)
	if !strings.Contains(p.Refuse, "First turn password login off, so root can sign in only with its key: sudo kiyesi fix ssh-password") {
		t.Errorf("passwords on: %q", p.Refuse)
	}
	// The safe order, command by command: root's keys checked first, the new
	// user given only the person's own key, and the test from a new terminal.
	for _, want := range []string{
		"sudo kiyesi keys\n",
		"sudo kiyesi keys remove <fingerprint>",
		"adduser <you> && usermod -aG sudo <you>",
		"never a copy of root's authorized_keys",
		"cat ~/.ssh/id_ed25519.pub",
		"install -d -m 700 -o <you> -g <you> /home/<you>/.ssh",
		"Keep this session open. From a new terminal: ssh <you>@this-server, then sudo -v",
		"Only when both work, signed in as <you>: sudo kiyesi fix ssh-root",
	} {
		if !strings.Contains(p.Refuse, want) {
			t.Errorf("the steps lack %q:\n%s", want, p.Refuse)
		}
	}
	if strings.Index(p.Refuse, "sudo kiyesi keys") > strings.Index(p.Refuse, "adduser") {
		t.Error("root's keys must be checked before the new user is made")
	}
}
