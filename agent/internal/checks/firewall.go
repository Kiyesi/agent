package checks

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// Firewall is what the scan could learn about the firewall on this server.
type Firewall struct {
	// Name is ufw, firewalld, nftables or iptables when one is on, or empty.
	Name string
	// Known is false when the state could not be read without root.
	Known bool
	// UFW is true when ufw is on. Rules are known only when UFWRulesKnown.
	UFW           bool
	UFWRulesKnown bool
	ufw           ufwRules
}

// Blocks reports whether the firewall on this server is known to block
// incoming connections to port from anywhere. When it cannot tell, it
// returns false, so a database is reported rather than missed.
func (f Firewall) Blocks(port int) bool {
	if !f.UFW || !f.UFWRulesKnown {
		return false
	}
	return !f.ufw.allows(port)
}

func readFirewall(ctx context.Context, sys *system.System) Firewall {
	if ufwOn(sys.FS) {
		fw := Firewall{Name: "ufw", Known: true, UFW: true}
		if sys.Root && sys.Exec.Has("ufw") {
			if out, err := sys.Exec.Run(ctx, "ufw", "status", "verbose"); err == nil {
				fw.ufw = parseUFW(out)
				fw.UFWRulesKnown = true
			}
		}
		return fw
	}
	if sys.Exec.Has("systemctl") {
		if out, _ := sys.Exec.Run(ctx, "systemctl", "is-active", "firewalld"); strings.TrimSpace(string(out)) == "active" {
			return Firewall{Name: "firewalld", Known: true}
		}
	}
	if !sys.Root {
		return Firewall{Known: false}
	}
	if sys.Exec.Has("nft") {
		if out, err := sys.Exec.Run(ctx, "nft", "list", "ruleset"); err == nil && nftFilters(out) {
			return Firewall{Name: "nftables", Known: true}
		}
	}
	if sys.Exec.Has("iptables") {
		if out, err := sys.Exec.Run(ctx, "iptables", "-S", "INPUT"); err == nil && iptablesFilters(out) {
			return Firewall{Name: "iptables", Known: true}
		}
	}
	return Firewall{Known: true}
}

// ufwOn reads etc/ufw/ufw.conf, which every user can read.
func ufwOn(fsys fs.FS) bool {
	data, err := fs.ReadFile(fsys, "etc/ufw/ufw.conf")
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "ENABLED=") {
			return strings.Trim(strings.TrimPrefix(line, "ENABLED="), `"'`) == "yes"
		}
	}
	return false
}

type ufwRule struct {
	from, to int // port range; 0,0 means every port
	allow    bool
}

type ufwRules struct {
	defaultAllow bool
	rules        []ufwRule
}

var ufwPorts = regexp.MustCompile(`^(\d+(?:[:,]\d+)*)(?:/(tcp|udp))?$`)

// parseUFW reads `ufw status verbose`. Only rules from Anywhere count: a
// rule for one address does not open a port to the internet.
func parseUFW(out []byte) ufwRules {
	var r ufwRules
	inTable := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Default:") {
			r.defaultAllow = strings.Contains(line, "allow (incoming)")
			continue
		}
		if strings.HasPrefix(line, "--") {
			inTable = true
			continue
		}
		if !inTable || line == "" {
			continue
		}
		f := strings.Fields(strings.ReplaceAll(line, "(v6)", ""))
		if len(f) < 3 {
			continue
		}
		to, action, from := f[0], strings.ToUpper(f[1]), f[len(f)-1]
		if from != "Anywhere" {
			continue
		}
		allow := action == "ALLOW" || action == "LIMIT"
		if !allow && action != "DENY" && action != "REJECT" {
			continue
		}
		if to == "Anywhere" {
			r.rules = append(r.rules, ufwRule{allow: allow})
			continue
		}
		m := ufwPorts.FindStringSubmatch(to)
		if m == nil || m[2] == "udp" {
			continue
		}
		for _, part := range strings.Split(m[1], ",") {
			lo, hi, isRange := strings.Cut(part, ":")
			a, _ := strconv.Atoi(lo)
			b := a
			if isRange {
				b, _ = strconv.Atoi(hi)
			}
			r.rules = append(r.rules, ufwRule{from: a, to: b, allow: allow})
		}
	}
	return r
}

// allows applies the first matching rule, as ufw does, then the default.
func (r ufwRules) allows(port int) bool {
	for _, rule := range r.rules {
		if (rule.from == 0 && rule.to == 0) || (port >= rule.from && port <= rule.to) {
			return rule.allow
		}
	}
	return r.defaultAllow
}

// nftFilters reports whether an nftables input chain drops or rejects traffic.
func nftFilters(out []byte) bool {
	s := string(out)
	for {
		i := strings.Index(s, "hook input")
		if i < 0 {
			return false
		}
		s = s[i:]
		end := strings.Index(s, "\n\t}")
		chain := s
		if end > 0 {
			chain = s[:end]
		}
		if strings.Contains(chain, "policy drop") || strings.Contains(chain, " drop") || strings.Contains(chain, " reject") {
			return true
		}
		s = s[len("hook input"):]
	}
}

// iptablesFilters reports whether the INPUT chain drops traffic by policy or rule.
func iptablesFilters(out []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "-P INPUT DROP" || (strings.HasPrefix(line, "-A INPUT") && (strings.HasSuffix(line, "-j DROP") || strings.HasSuffix(line, "-j REJECT") || strings.Contains(line, "-j REJECT "))) {
			return true
		}
	}
	return false
}
