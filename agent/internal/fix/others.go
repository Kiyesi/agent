package fix

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// firewall turns ufw on, open only to SSH and the ports marked as opened
// on purpose. SSH is allowed before ufw starts, so the session stays open.
type firewall struct{}

func (firewall) Name() string      { return "firewall" }
func (firewall) Targets() []Target { return []Target{{"firewall", "off"}} }

func (firewall) open(ctx context.Context, h Host, in Input) []int {
	open := sshPorts(ctx, h)
	for _, p := range in.Cfg.Ports.Allowed {
		if !slices.Contains(open, p) {
			open = append(open, p)
		}
	}
	slices.Sort(open)
	return open
}

func (f firewall) Plan(ctx context.Context, h Host, in Input) Plan {
	p := Plan{Done: "Firewall on", Undoable: true}
	if !h.Has("ufw") && !h.Has("apt-get") {
		p.Refuse = "Kiyesi turns on ufw, which this system does not have. Turn on its own firewall, keeping your SSH port open."
		return p
	}
	open := f.open(ctx, h, in)
	ssh := sshPorts(ctx, h)
	var names []string
	for _, port := range open {
		if slices.Contains(ssh, port) {
			names = append(names, fmt.Sprintf("SSH (%d)", port))
		} else {
			names = append(names, strconv.Itoa(port))
		}
	}
	install := ""
	if !h.Has("ufw") {
		install = "Installs ufw and "
	}
	p.Say = fmt.Sprintf("%sturns the firewall on, open only to: %s.", install, strings.Join(names, ", "))
	if install == "" {
		p.Say = strings.ToUpper(p.Say[:1]) + p.Say[1:]
	}
	var closing []string
	for _, port := range in.Public {
		// docker-proxy listens for published ports, and ufw does not close them.
		if !slices.Contains(open, port) && !slices.Contains(in.Docker, port) {
			closing = append(closing, strconv.Itoa(port))
		}
	}
	if len(closing) > 0 {
		p.Warn = append(p.Warn, fmt.Sprintf("These ports are open to the internet now and will be closed: %s. If one must stay open, add it under ports.allowed in /etc/kiyesi/config.yaml first.", strings.Join(closing, ", ")))
		p.Confirm = true
	}
	p.Warn = append(p.Warn, "Ports that Docker publishes are not closed by ufw: the docker-firewall finding says what to do about those.")
	return p
}

func (f firewall) Apply(ctx context.Context, h Host, in Input, c *Changes) error {
	open := f.open(ctx, h, in)
	if !h.Has("ufw") {
		if _, err := c.Run(ctx, "apt-get", "install", "-y", "-q", "ufw"); err != nil {
			return aptProblem(err)
		}
		// Undo leaves the firewall off, then removes what this fix installed.
		defer func() { _ = c.Then("apt-get", "remove", "-y", "-q", "ufw") }()
	}
	for _, file := range []string{"/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		if err := c.Keep(file); err != nil {
			return err
		}
	}
	if err := c.Then("ufw", "--force", "disable"); err != nil {
		return err
	}
	for _, port := range open {
		if _, err := c.Run(ctx, "ufw", "allow", strconv.Itoa(port)+"/tcp"); err != nil {
			return err
		}
	}
	if _, err := c.Run(ctx, "ufw", "--force", "enable"); err != nil {
		return err
	}
	out, err := c.Run(ctx, "ufw", "status")
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "Status: active") {
		return errors.New("ufw did not turn on")
	}
	return nil
}

// loginProtection installs or starts fail2ban, which blocks an address
// after repeated failed logins.
type loginProtection struct{}

func (loginProtection) Name() string      { return "login-protection" }
func (loginProtection) Targets() []Target { return []Target{{"login-protection", "missing"}} }

const fail2banClient = "/usr/bin/fail2ban-client"

func installed(h Host, file string) bool {
	_, err := h.Lstat(file)
	return err == nil
}

func (loginProtection) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Done: "fail2ban on", Undoable: true}
	if !h.Has("systemctl") || (!installed(h, fail2banClient) && !h.Has("apt-get")) {
		p.Refuse = "Kiyesi installs fail2ban with apt and systemd, which this system does not have. Install fail2ban, or turn SSH password login off."
		return p
	}
	if installed(h, fail2banClient) {
		p.Say = "Starts fail2ban, which is installed but not running. It blocks an address after repeated failed logins."
	} else {
		p.Say = "Installs fail2ban, which blocks an address after repeated failed logins."
	}
	// Decided after ssh-password runs: if it is declined or fails, the
	// passwords stay, and so does the need for this.
	if in.Planned["ssh-password"] {
		p.Say += " Skipped if ssh-password turns password login off first."
		p.Unless = "ssh-password"
		p.UnlessSkip = "Not needed: with SSH password login off, there is no password to guess."
	}
	return p
}

func (loginProtection) Apply(ctx context.Context, h Host, _ Input, c *Changes) error {
	if err := c.Then("systemctl", "disable", "--now", "fail2ban"); err != nil {
		return err
	}
	if !installed(h, fail2banClient) {
		pkgs := []string{"install", "-y", "-q", "fail2ban"}
		// Without auth.log (Debian 12 and later), fail2ban reads the journal.
		journal := !installed(h, "/var/log/auth.log")
		if journal {
			pkgs = append(pkgs, "python3-systemd")
		}
		if _, err := c.Run(ctx, "apt-get", "update", "-q"); err != nil {
			return aptProblem(err)
		}
		if _, err := c.Run(ctx, "apt-get", pkgs...); err != nil {
			return aptProblem(err)
		}
		if err := c.Then("apt-get", "remove", "-y", "-q", "fail2ban"); err != nil {
			return err
		}
		if journal {
			if err := c.Write("/etc/fail2ban/jail.d/kiyesi.conf", []byte("# Added by kiyesi fix: watch SSH logins in the journal.\n[sshd]\nenabled = true\nbackend = systemd\n"), 0o644); err != nil {
				return err
			}
		}
	}
	if _, err := c.Run(ctx, "systemctl", "enable", "--now", "fail2ban"); err != nil {
		return err
	}
	for range 15 {
		if out, _ := h.Run(ctx, "systemctl", "is-active", "fail2ban"); strings.TrimSpace(string(out)) == "active" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("fail2ban did not start: see sudo journalctl -u fail2ban")
}

// secretFile makes files holding secrets unreadable to other users. Their
// owner and group keep access, so the app that reads them still can.
type secretFile struct{}

func (secretFile) Name() string      { return "secret-files" }
func (secretFile) Targets() []Target { return []Target{{"secrets-in-files", "world-readable"}} }

func (secretFile) paths(h Host, in Input) (ok, skipped []string) {
	for _, f := range in.Findings {
		p := f.Vars["path"]
		info, err := h.Lstat(p)
		if !strings.HasPrefix(p, "/") || err != nil || !info.Mode().IsRegular() {
			skipped = append(skipped, p)
			continue
		}
		ok = append(ok, p)
	}
	return ok, skipped
}

func (s secretFile) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Done: "Secret files closed to other users", Undoable: true}
	ok, skipped := s.paths(h, in)
	if len(ok) == 0 {
		p.Refuse = "The files are links or have moved, so Kiyesi leaves them to you."
		return p
	}
	p.Say = fmt.Sprintf("Makes %s unreadable to other users on this server; its owner and group keep access: %s.", plural(len(ok), "1 file", "files"), strings.Join(ok, ", "))
	if len(ok) > 1 {
		p.Say = strings.Replace(p.Say, "its owner and group", "their owners and groups", 1)
	}
	if len(skipped) > 0 {
		p.Warn = append(p.Warn, "Left alone, as they are links or have moved: "+strings.Join(skipped, ", "))
	}
	return p
}

func (s secretFile) Apply(_ context.Context, h Host, in Input, c *Changes) error {
	ok, _ := s.paths(h, in)
	for _, p := range ok {
		info, err := h.Lstat(p)
		if err != nil {
			return err
		}
		if err := c.Chmod(p, info.Mode().Perm()&^fs.FileMode(0o007)); err != nil {
			return err
		}
	}
	return nil
}

// certificates renews what certbot looks after. Certificates Caddy or
// someone else issued need a person.
type certificates struct{}

func (certificates) Name() string { return "certificates" }
func (certificates) Targets() []Target {
	return []Target{{"certificates", "expiring"}, {"certificates", "expired"}}
}

func (certificates) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Done: "Certificates renewed"}
	if !h.Has("certbot") {
		p.Refuse = "certbot is not installed, so Kiyesi cannot renew these. Renew them with whoever issued them."
		return p
	}
	var hosts []string
	for _, f := range in.Findings {
		if h := f.Vars["host"]; h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	p.Say = "Renews the certificates certbot looks after: " + strings.Join(hosts, ", ") + ". Nothing to undo."
	return p
}

func (certificates) Apply(ctx context.Context, _ Host, _ Input, c *Changes) error {
	_, err := c.Run(ctx, "certbot", "renew", "--non-interactive")
	return err
}

// updates installs the waiting updates. It cannot be undone, and it never
// restarts the server: it says when a restart is needed.
type updates struct{}

func (updates) Name() string { return "updates" }
func (updates) Targets() []Target {
	return []Target{{"updates", "waiting"}, {"vulnerabilities", "system"}}
}

func (updates) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Done: "Updates installed"}
	if !h.Has("apt-get") {
		p.Refuse = "Kiyesi installs updates with apt, which this system does not have. Use its own package manager."
		return p
	}
	count := ""
	for _, f := range in.Findings {
		if n := f.Vars["count"]; n != "" && n != "0" {
			count = n
			break
		}
	}
	p.Say = "Installs the waiting updates"
	if count != "" {
		p.Say += " (" + count + " for security)"
	}
	p.Say += ". This one cannot be undone, and can take a few minutes."
	p.Warn = []string{"Programs restart as their updates install. Kiyesi never restarts the server itself: it says when that is needed."}
	return p
}

func (updates) Apply(ctx context.Context, h Host, _ Input, c *Changes) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	steps := [][]string{
		{"update", "-q"},
		{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade", "--with-new-pkgs"},
		{"-y", "-q", "autoremove", "--purge"},
	}
	for _, s := range steps {
		if _, err := c.Run(ctx, "apt-get", s...); err != nil {
			return aptProblem(err)
		}
	}
	if installed(h, "/var/run/reboot-required") {
		c.rec.Done += ". Restart the server when it suits you: sudo reboot"
	}
	return nil
}

// dockerCleanup gives back the disk Docker holds for nothing: images no
// container uses that were created over a week ago, and build cache over a
// week old. Docker's until filter reads when an image was built, not when
// it stopped being used, so an old image replaced today goes too.
// Containers and volumes are never touched: a stopped container or an
// unused volume can hold data.
type dockerCleanup struct{}

func (dockerCleanup) Name() string      { return "docker-cleanup" }
func (dockerCleanup) Targets() []Target { return []Target{{"leftovers", "docker-waste"}} }

func (dockerCleanup) Plan(_ context.Context, h Host, in Input) Plan {
	p := Plan{Done: "Unused Docker images and build cache removed"}
	if !h.Has("docker") {
		p.Refuse = "The docker command is not installed here. Run docker image prune -a --filter until=168h where it is."
		return p
	}
	size := ""
	for _, f := range in.Findings {
		if s := f.Vars["size"]; s != "" {
			size = " Of the " + s + " Docker keeps unused now, only that part goes, so less may be freed. An image you replaced today goes too if it was built over a week ago: to keep one for rolling back, tag it or start a container from it first."
			break
		}
	}
	p.Say = "Removes Docker images no container uses that were created over a week ago, and build cache over a week old." + size +
		" Containers and volumes are never touched. This one cannot be undone: a removed image is pulled or built again when it is needed."
	return p
}

// reclaimed reads "Total reclaimed space: 1.2GB" (images) or "Total: 1.2GB"
// (build cache, in newer Docker) from docker's answer.
var reclaimed = regexp.MustCompile(`Total(?: reclaimed space)?:\s*(\S+)`)

func (dockerCleanup) Apply(ctx context.Context, _ Host, _ Input, c *Changes) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	out, err := c.Run(ctx, "docker", "image", "prune", "-a", "-f", "--filter", "until=168h")
	if err != nil {
		return err
	}
	freed := []string{}
	if m := reclaimed.FindSubmatch(out); m != nil && string(m[1]) != "0B" {
		freed = append(freed, string(m[1])+" of images")
	}
	// Build cache is a bonus: an old Docker without BuildKit has none to remove.
	if out, err := c.Run(ctx, "docker", "builder", "prune", "-f", "--filter", "until=168h"); err == nil {
		if m := reclaimed.FindSubmatch(out); m != nil && string(m[1]) != "0B" {
			freed = append(freed, string(m[1])+" of build cache")
		}
	}
	if len(freed) > 0 {
		c.rec.Done += ": " + strings.Join(freed, " and ") + " freed"
	} else {
		c.rec.Done = "No unused image was created over a week ago and no build cache was over a week old, so nothing was removed"
	}
	return nil
}

// aptProblem says what to do when apt is busy, in words.
func aptProblem(err error) error {
	if strings.Contains(err.Error(), "Could not get lock") || strings.Contains(err.Error(), "is held by process") {
		return errors.New("another update is running (often the server's automatic updates). Try again in a few minutes")
	}
	return err
}
