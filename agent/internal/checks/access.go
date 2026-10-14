package checks

import (
	"context"
	"strings"
)

type sshCheck struct{}

func (sshCheck) ID() string { return "ssh" }

func (sshCheck) Run(ctx context.Context, env *Env) Result {
	s := env.SSH(ctx)
	if !s.Present {
		return PassNone()
	}
	var found []Finding
	if s.PasswordLogin {
		found = append(found, Found("password", nil))
	}
	if s.RootLogin {
		found = append(found, Found("root", nil))
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(nil)
}

type firewallCheck struct{}

func (firewallCheck) ID() string { return "firewall" }

func (firewallCheck) Run(ctx context.Context, env *Env) Result {
	fw := env.Firewall(ctx)
	switch {
	case fw.Name != "":
		return Pass(map[string]string{"firewall": fw.Name})
	case !fw.Known:
		return NeedsRoot()
	default:
		return Fail(Found("off", nil))
	}
}

type loginProtectionCheck struct{}

func (loginProtectionCheck) ID() string { return "login-protection" }

// guards are the programs that lock out an address after repeated failures.
var guards = []struct{ unit, name string }{
	{"fail2ban", "fail2ban"},
	{"sshguard", "sshguard"},
	{"crowdsec", "CrowdSec"},
}

func (loginProtectionCheck) Run(ctx context.Context, env *Env) Result {
	s := env.SSH(ctx)
	if !s.Present {
		return Pass(map[string]string{"protection": "No SSH server, so there is no SSH login to guess"})
	}
	if !s.PasswordLogin {
		return Pass(map[string]string{"protection": "SSH password login is off, so there is no password to guess"})
	}
	if env.Sys.Exec.Has("systemctl") {
		for _, g := range guards {
			out, _ := env.Sys.Exec.Run(ctx, "systemctl", "is-active", g.unit)
			if strings.TrimSpace(string(out)) == "active" {
				return Pass(map[string]string{"protection": g.name + " is running"})
			}
		}
	}
	return Fail(Found("missing", nil))
}
