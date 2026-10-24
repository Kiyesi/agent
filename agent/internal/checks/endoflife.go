package checks

import (
	"context"
	"encoding/json"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

// endOfLifeCheck says whether the system still gets security fixes: past the
// last day of its release's fixes, nothing is fixed any more, whatever is
// installed. The dates are built into kiyesi (packs/eol.yaml), so the check
// downloads nothing. Ubuntu Pro's extended fixes count when they are on.
// Debian's long-term support counts as fixes, with a note while it runs,
// since it covers most packages but not all.
//
// The dates are the vendors' own where they state them:
// https://ubuntu.com/about/release-cycle, https://www.debian.org/releases/,
// https://wiki.debian.org/LTS, https://access.redhat.com/support/policy/updates/errata
// (Maintenance Support, the last free phase). scripts/eol-pack.py names
// each source.
type endOfLifeCheck struct{}

func (endOfLifeCheck) ID() string { return "end-of-life" }

// endingSoon is how many days before the end the check warns: Ubuntu's next
// release comes out about three months before the last one's fixes end, so
// the warning arrives when there is somewhere to move to.
const endingSoon = 90

func (endOfLifeCheck) Run(_ context.Context, env *Env) Result {
	table, err := packs.LoadEndOfLife()
	if err != nil {
		return Failed(err)
	}
	os := env.Sys.OS
	name := os.Name
	if name == "" {
		name = os.ID + " " + os.VersionID
	}
	if !table.Knows(os.ID) {
		return Skip("unknown-system", map[string]string{"os": name})
	}
	system, _, rel, ok := table.Lookup(os.ID, os.VersionID, os.Name)
	if !ok {
		return Skip("unknown-release", map[string]string{"os": name, "fetched": table.Fetched})
	}
	end, pro := rel.Fixes, false
	if system == "ubuntu" && !rel.Extended.IsZero() && proFixesOn(env.Sys.FS) {
		end, pro = rel.Extended, true
	}
	// Whole days from today to the last day of fixes, which is itself a
	// day of fixes: 0 on the last day, below 0 after it.
	now := env.Sys.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	days := int(end.Sub(today).Hours() / 24)
	vars := map[string]string{"os": name, "date": end.Format("2 Jan 2006")}
	variant := map[string]string{"ubuntu": "ubuntu", "debian": "debian", "rhel": "rhel", "rocky": "rhel", "almalinux": "rhel", "ol": "rhel"}[system]
	switch {
	case days < 0:
		return Fail(Finding{Key: "ended", Variant: variant, Vars: vars})
	case days <= endingSoon:
		vars["days"] = strconv.Itoa(days)
		return Fail(Finding{Key: "ending", Variant: variant, Vars: vars})
	}
	if !rel.Regular.IsZero() && today.After(rel.Regular) {
		// Debian's own security team has handed over to long-term support.
		return Fail(Finding{Key: "lts", Variant: variant, Vars: vars})
	}
	if pro {
		vars["with"] = " with Ubuntu Pro"
	} else {
		vars["with"] = ""
	}
	return Pass(vars)
}

// proFixesOn says whether Ubuntu Pro's extended fixes for the system
// (esm-infra) are switched on, from Pro's own status file.
func proFixesOn(fsys fs.FS) bool {
	data, err := fs.ReadFile(fsys, "var/lib/ubuntu-advantage/status.json")
	if err != nil {
		return false
	}
	var s struct {
		Services []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"services"`
	}
	if json.Unmarshal(data, &s) != nil {
		return false
	}
	for _, sv := range s.Services {
		if sv.Name == "esm-infra" && strings.EqualFold(sv.Status, "enabled") {
			return true
		}
	}
	return false
}
