// Package fix is kiyesi fix: the only code in Kiyesi that changes a server.
// The scan and the agent's service never use it; it runs only when a person
// types sudo kiyesi fix and says yes. Each fix is a small type with the same
// interface, like the checks. Before a fix changes a file it saves it, so
// kiyesi fix undo can put it back, and a fix that fails halfway is put back
// at once.
package fix

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
)

// Target is one finding a fix answers: a check's id and the finding's key.
type Target struct{ Check, Key string }

// Input is what a fix knows when it plans: its findings from this scan,
// the settings, and the facts the scan read.
type Input struct {
	Findings []checks.Finding
	Cfg      config.Config
	// User is the person who ran sudo (SUDO_USER), or root.
	User string
	// SSH is the SSH server's settings, as the scan read them.
	SSH checks.SSH
	// Public are the ports open on a public address, from the scan.
	Public []int
	// Docker are the ports Docker publishes: ufw does not close them.
	Docker []int
	// Planned names the other fixes chosen in this run, so one can step
	// aside when another makes it unneeded.
	Planned map[string]bool
}

// Plan is what a fix will do, in plain words, or why it will not.
type Plan struct {
	// Say is what it changes, for the list: "Turns SSH password login off."
	Say string
	// Refuse, when set, is why it will not run, and what to do instead.
	Refuse string
	// Warn is said before asking, such as the ports a firewall will close.
	Warn []string
	// Confirm is true when Warn is serious enough to ask on its own.
	Confirm bool
	// Undoable is false for a change that cannot be taken back, such as
	// installing updates. The list says so.
	Undoable bool
	// Skip, when set, means this fix is not needed in this run, and why.
	Skip string
	// Unless names another fix in this run that makes this one unneeded
	// once it has worked; UnlessSkip says why, when that happens.
	Unless, UnlessSkip string
	// Done is the past tense for the result line: "SSH password login off".
	Done string
}

// Fixer is one fix.
type Fixer interface {
	// Name is the word after kiyesi fix, such as ssh-password.
	Name() string
	// Targets are the findings it answers.
	Targets() []Target
	// Plan says what it will do. It changes nothing.
	Plan(ctx context.Context, h Host, in Input) Plan
	// Apply makes the change, saving through c whatever undo needs.
	Apply(ctx context.Context, h Host, in Input, c *Changes) error
}

// All returns the fixes, in the order they run: SSH first, as a firewall
// must know the SSH port, then the rest.
func All() []Fixer {
	return []Fixer{
		sshPassword{}, sshRoot{}, firewall{}, loginProtection{},
		secretFile{}, certificates{}, updates{}, dockerCleanup{},
	}
}

// ByName returns the fix with this name, or nil.
func ByName(name string) Fixer {
	for _, f := range All() {
		if f.Name() == name {
			return f
		}
	}
	return nil
}

// Names lists every fix's name, sorted, for help and errors.
func Names() []string {
	var out []string
	for _, f := range All() {
		out = append(out, f.Name())
	}
	sort.Strings(out)
	return out
}

// For returns the fix that answers a finding, or nil. Only a finding's
// usual fix counts: a variant (such as a certificate Caddy looks after)
// needs a person.
func For(check string, f checks.Finding) Fixer {
	if f.Variant != "" {
		return nil
	}
	for _, x := range All() {
		for _, t := range x.Targets() {
			if t.Check == check && t.Key == f.Key {
				return x
			}
		}
	}
	return nil
}

// ErrNotForThisSystem is a fix asked for on a system it does not know.
var ErrNotForThisSystem = errors.New("not for this system yet")

// Failed is a fix that did not finish, with how much of the server it may
// have left changed.
type Failed struct {
	Err error
	// Changed is true when the server may not be as it was: a fix that
	// cannot be undone stopped partway (some updates installed), or
	// putting a fix back failed too.
	Changed bool
}

func (e *Failed) Error() string { return e.Err.Error() }
func (e *Failed) Unwrap() error { return e.Err }

// NotKept is a fix that worked whose undo record could not be saved: the
// change is made, but kiyesi fix undo cannot put it back.
type NotKept struct{ Err error }

func (e *NotKept) Error() string {
	return "its undo record could not be saved, so kiyesi fix undo cannot put it back: " + e.Err.Error()
}
func (e *NotKept) Unwrap() error { return e.Err }

// Run applies one fix with a record of what it changed. If the fix fails,
// everything it changed is put back before the error, a *Failed, is
// returned. When the fix worked but its record could not be saved, the
// record comes back with a *NotKept.
func Run(ctx context.Context, h Host, s *Store, f Fixer, in Input, p Plan) (*Record, error) {
	rec, err := s.Begin(f.Name(), p.Done, in.User, p.Undoable)
	if err != nil {
		return nil, &Failed{Err: fmt.Errorf("cannot keep a record for undo, so it did not start: %w", err)}
	}
	c := &Changes{h: h, s: s, rec: rec}
	if err := f.Apply(ctx, h, in, c); err != nil {
		if uerr := undo(ctx, h, s, rec); uerr != nil {
			return nil, &Failed{Err: fmt.Errorf("%v; putting it back also failed: %v. What was saved is in %s", err, uerr, s.dirOf(rec.ID)), Changed: true}
		}
		s.forget(rec.ID)
		// A fix that cannot be undone (updates, certificates, a Docker
		// clean-up) may have done part of its work before it stopped.
		return nil, &Failed{Err: err, Changed: !p.Undoable}
	}
	if err := s.save(rec); err != nil {
		return rec, &NotKept{Err: err}
	}
	return rec, nil
}
