package fix

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// The SSH fixes add one small file to sshd_config.d, which SSH reads before
// the rest of its settings. SSH checks the setting (sshd -t) before it is
// reloaded, never restarted, so the session that runs the fix stays open.

const sshDropIn = "/etc/ssh/sshd_config.d"

type sshPassword struct{}

func (sshPassword) Name() string      { return "ssh-password" }
func (sshPassword) Targets() []Target { return []Target{{"ssh", "password"}} }

func (sshPassword) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Say: "Turns SSH password login off, so only keys can sign in.", Done: "SSH password login off", Undoable: true}
	if why := sshReady(h); why != "" {
		p.Refuse = why
		return p
	}
	n := keysOf(h, in.User)
	if n == 0 {
		p.Refuse = fmt.Sprintf("%s has no SSH key on this server, so turning passwords off could lock you out. Add your key first (ssh-copy-id %s@this-server, from your own computer), sign in with it, then run this again.", in.User, in.User)
		return p
	}
	p.Say = fmt.Sprintf("Turns SSH password login off. %s has %s here, so you stay in.", in.User, plural(n, "an SSH key", "SSH keys"))
	p.Warn = []string{"Keep this session open, and check that a new SSH login works before you close it."}
	return p
}

func (sshPassword) Apply(ctx context.Context, h Host, _ Input, c *Changes) error {
	return sshSet(ctx, h, c, "00-kiyesi-no-password.conf",
		"# Added by kiyesi fix: keys only. Undo with: sudo kiyesi fix undo\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
		map[string]string{"passwordauthentication": "no"})
}

type sshRoot struct{}

func (sshRoot) Name() string      { return "ssh-root" }
func (sshRoot) Targets() []Target { return []Target{{"ssh", "root"}} }

func (sshRoot) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Say: "Turns SSH login as root off. You sign in as yourself and use sudo.", Done: "SSH root login off", Undoable: true}
	if why := sshReady(h); why != "" {
		p.Refuse = why
		return p
	}
	if in.User == "" || in.User == "root" {
		// Signed in as root: turning root login off could lock them out.
		// Say what is already true, and the step that comes first.
		if in.SSH.PasswordLogin {
			p.Refuse = "You are signed in as root, so turning root login off could lock you out. First turn password login off (sudo kiyesi fix ssh-password): root can then sign in only with its key. To turn root login off entirely, make a user of your own with sudo and an SSH key, sign in as that user, then run sudo kiyesi fix ssh-root."
		} else {
			p.Refuse = "You are signed in as root, so turning root login off could lock you out. Password login is already off, so root can sign in only with its key. To turn root login off entirely, make a user of your own with sudo and an SSH key, sign in as that user, then run sudo kiyesi fix ssh-root."
		}
		return p
	}
	if keysOf(h, in.User) == 0 {
		p.Refuse = fmt.Sprintf("%s has no SSH key on this server, so you might not get back in. Add your key first (ssh-copy-id %s@this-server, from your own computer), then run this again.", in.User, in.User)
		return p
	}
	p.Say = fmt.Sprintf("Turns SSH login as root off. You sign in as %s, with your key, and use sudo.", in.User)
	return p
}

func (sshRoot) Apply(ctx context.Context, h Host, _ Input, c *Changes) error {
	return sshSet(ctx, h, c, "00-kiyesi-no-root.conf",
		"# Added by kiyesi fix: no root login. Undo with: sudo kiyesi fix undo\nPermitRootLogin no\n",
		map[string]string{"permitrootlogin": "no"})
}

// sshReady says why the SSH fixes cannot run here, or "".
func sshReady(h Host) string {
	if !h.Has("sshd") || !h.Has("systemctl") {
		return "This server's SSH is not the usual OpenSSH with systemd, so Kiyesi leaves it to you. The command to run is in the finding."
	}
	data, err := h.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "Kiyesi cannot read /etc/ssh/sshd_config, so it leaves SSH to you."
	}
	if !includesDropIn(data) {
		return "This server's /etc/ssh/sshd_config does not read the files in /etc/ssh/sshd_config.d, so Kiyesi leaves it to you. Change the setting in sshd_config itself, then: sudo systemctl reload ssh"
	}
	return ""
}

// includesDropIn is true when sshd_config reads sshd_config.d/*.conf
// before any Match block, so a setting there applies to every login.
func includesDropIn(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "match":
			return false
		case "include":
			for _, p := range f[1:] {
				if !strings.HasPrefix(p, "/") {
					p = path.Join("/etc/ssh", p)
				}
				if p == sshDropIn+"/*.conf" || p == sshDropIn+"/*" {
					return true
				}
			}
		}
	}
	return false
}

// sshSet writes the file, checks it, reloads SSH and reads the setting
// back. Any failure returns an error, and the caller puts it all back.
func sshSet(ctx context.Context, h Host, c *Changes, name, body string, want map[string]string) error {
	file := sshDropIn + "/" + name
	if err := c.Write(file, []byte(body), 0o644); err != nil {
		return err
	}
	if _, err := c.Run(ctx, "sshd", "-t"); err != nil {
		return fmt.Errorf("SSH refused the new setting, so nothing was changed: %w", err)
	}
	unit := sshUnit(ctx, h)
	if err := c.Then("systemctl", "reload", unit); err != nil {
		return err
	}
	if _, err := c.Run(ctx, "systemctl", "reload", unit); err != nil {
		return err
	}
	out, err := c.Run(ctx, "sshd", "-T")
	if err != nil {
		return err
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			if _, set := got[k]; !set {
				got[k] = strings.ToLower(v)
			}
		}
	}
	for k, v := range want {
		if got[k] != v {
			return fmt.Errorf("SSH still has %s %s: a setting earlier in /etc/ssh/sshd_config wins. Change it there, then: sudo systemctl reload %s", k, got[k], unit)
		}
	}
	return nil
}

// sshUnit is the SSH service's name: ssh on Debian and Ubuntu, sshd elsewhere.
func sshUnit(ctx context.Context, h Host) string {
	if out, _ := h.Run(ctx, "systemctl", "is-active", "ssh"); strings.TrimSpace(string(out)) == "active" {
		return "ssh"
	}
	return "sshd"
}

// keysOf counts the keys in a user's authorized_keys.
func keysOf(h Host, user string) int {
	home := homeOf(h, user)
	if home == "" {
		return 0
	}
	data, err := h.ReadFile(home + "/.ssh/authorized_keys")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

// homeOf reads a user's home folder from /etc/passwd.
func homeOf(h Host, user string) string {
	data, err := h.ReadFile("/etc/passwd")
	if err != nil || user == "" {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 6 && f[0] == user {
			return f[5]
		}
	}
	return ""
}

// sshPorts are the ports SSH listens on, from sshd -T, or 22.
func sshPorts(ctx context.Context, h Host) []int {
	var ports []int
	if h.Has("sshd") {
		if out, err := h.Run(ctx, "sshd", "-T"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "port "); ok {
					if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && p > 0 && p < 65536 {
						ports = append(ports, p)
					}
				}
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return strconv.Itoa(n) + " " + strings.TrimPrefix(strings.TrimPrefix(many, "an "), "a ")
}
