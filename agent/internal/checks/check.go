// Package checks holds the health and security checks. Each one is a small
// type with an id and a Run method, so every check is run, tested and
// documented the same way. Checks hold no wording: they return keys and
// values, and the wording comes from packs/checks/en.yaml.
package checks

import (
	"context"
	"fmt"
)

// Check is the interface every check implements. Run must only read.
type Check interface {
	ID() string
	Run(ctx context.Context, env *Env) Result
}

// Status is the outcome of one check.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Finding is one problem: the key of its wording in the pack, an optional
// fix variant, and the values for the wording's placeholders.
type Finding struct {
	Key     string
	Variant string
	Vars    map[string]string
	// Confidence, when set, replaces the pack's confidence for this
	// finding: confirmed or likely.
	Confidence string
}

// Location is one row of the report's data-location section: where a
// server, database, backup or outside service is.
type Location struct {
	Kind       string // Server, Database, Backup or Service
	Name       string // what it is, such as "redis (this server)"
	Place      string // "London, UK", or empty when unknown
	Country    string // ISO code, or empty when unknown
	Confidence string // confirmed, likely, or empty when unknown
	Review     bool   // an outside service, listed for review and never flagged
	// Host is a database's or backup's address, without port or credentials,
	// so the service can place one the agent could not.
	Host string
	// Provider is the provider's name when known, such as DigitalOcean.
	Provider string
	// Private is set on a database on the server's private network.
	Private bool
	// Payment is set on a database the settings tag as holding payment data.
	Payment bool
}

// Result is what a check found.
type Result struct {
	Status   Status
	Findings []Finding
	// None means there was nothing to check, such as no containers. It
	// counts as passed, and uses the pack's passed-none line.
	None bool
	// Vars fill the pack's passed line.
	Vars map[string]string
	// NoHome means no home country is chosen, so nothing was compared with
	// one. It uses the pack's passed-no-home line.
	NoHome bool
	// Locations are the rows this check adds to the data-location section.
	Locations []Location
	// SkipKey names the reason for a skip: a key in the check's own skips,
	// or in the pack's shared skips.
	SkipKey  string
	SkipVars map[string]string
}

// Pass is a check that found nothing wrong.
func Pass(vars map[string]string) Result { return Result{Status: StatusPass, Vars: vars} }

// PassNone is a check with nothing to check.
func PassNone() Result { return Result{Status: StatusPass, None: true} }

// Fail is a check with at least one finding.
func Fail(fs ...Finding) Result { return Result{Status: StatusFail, Findings: fs} }

// Skip is a check that could not run. It never counts as passed.
func Skip(key string, vars map[string]string) Result {
	return Result{Status: StatusSkip, SkipKey: key, SkipVars: vars}
}

// NeedsRoot is a check that could not read what it needs without root.
func NeedsRoot() Result { return Skip("needs-root", nil) }

// Failed is a check that hit an unexpected error.
func Failed(err error) Result { return Skip("failed", map[string]string{"reason": err.Error()}) }

// Found makes a finding.
func Found(key string, vars map[string]string) Finding { return Finding{Key: key, Vars: vars} }

// Registry holds the checks by id, in the order the report lists them.
type Registry struct {
	ordered []Check
}

// NewRegistry returns a registry of the given checks. Each id must be
// unique and non-empty.
func NewRegistry(cs ...Check) (*Registry, error) {
	seen := map[string]bool{}
	for _, c := range cs {
		id := c.ID()
		if id == "" {
			return nil, fmt.Errorf("check with empty id: %T", c)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate check id %q", id)
		}
		seen[id] = true
	}
	return &Registry{ordered: cs}, nil
}

// All returns the checks in report order.
func (r *Registry) All() []Check { return r.ordered }

// Default returns the 22 checks, in the order of the PRD's tables: health,
// security, then data location.
func Default() *Registry {
	r, err := NewRegistry(
		loadCheck{}, memoryCheck{}, diskCheck{}, containersCheck{}, oomCheck{},
		certificatesCheck{}, backupsCheck{}, updatesCheck{},
		openPortsCheck{}, exposedDatabasesCheck{}, dockerFirewallCheck{}, sshCheck{},
		firewallCheck{}, loginProtectionCheck{}, secretsCheck{}, riskyContainersCheck{},
		vulnerabilitiesCheck{},
		serverLocationCheck{}, databaseConnectionsCheck{}, backupDestinationsCheck{},
		outsideServicesCheck{}, paymentDataCheck{},
	)
	if err != nil {
		panic(err) // the list above is fixed; a duplicate is a programming error
	}
	return r
}
