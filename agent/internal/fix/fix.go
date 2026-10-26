// Package fix is what is left of kiyesi fix's changes: Kiyesi never changes
// a server. It names the fixes, so sudo kiyesi fix <name> can narrow its
// list of suggestions to the findings one covers, and it reads the records
// kiyesi fix kept before 0.40.0, when it could make a change after a yes,
// so kiyesi fix undo can print the commands that put one back.
package fix

import "sort"

// Target is one finding a fix covers: a check's id and the finding's key.
type Target struct{ Check, Key string }

// Fixer is one fix by name, with the findings it covers.
type Fixer struct {
	name    string
	targets []Target
}

// Name is the word after kiyesi fix, such as ssh-password.
func (f *Fixer) Name() string { return f.name }

// Targets are the findings it covers.
func (f *Fixer) Targets() []Target { return f.targets }

var all = []*Fixer{
	{"ssh-password", []Target{{"ssh", "password"}}},
	{"ssh-root", []Target{{"ssh", "root"}}},
	{"firewall", []Target{{"firewall", "off"}}},
	{"login-protection", []Target{{"login-protection", "missing"}}},
	{"secret-files", []Target{{"secrets-in-files", "world-readable"}, {"secrets-in-files", "readable-closed"}}},
	{"certificates", []Target{{"certificates", "expiring"}, {"certificates", "expired"}}},
	{"updates", []Target{{"updates", "waiting"}, {"vulnerabilities", "system"}}},
	{"docker-cleanup", []Target{{"leftovers", "docker-waste"}}},
}

// ByName returns the fix with this name, or nil.
func ByName(name string) *Fixer {
	for _, f := range all {
		if f.name == name {
			return f
		}
	}
	return nil
}

// Names lists every fix's name, sorted, for help and errors.
func Names() []string {
	var out []string
	for _, f := range all {
		out = append(out, f.name)
	}
	sort.Strings(out)
	return out
}
