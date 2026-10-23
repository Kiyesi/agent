package checks

import (
	"context"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

type fakeCheck struct{ id string }

func (f fakeCheck) ID() string                       { return f.id }
func (f fakeCheck) Run(context.Context, *Env) Result { return Pass(nil) }

func TestNewRegistryKeepsOrder(t *testing.T) {
	r, err := NewRegistry(fakeCheck{"b"}, fakeCheck{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if all := r.All(); all[0].ID() != "b" || all[1].ID() != "a" {
		t.Errorf("order changed: %v", all)
	}
}

func TestNewRegistryRejectsDuplicateAndEmptyIDs(t *testing.T) {
	if _, err := NewRegistry(fakeCheck{"a"}, fakeCheck{"a"}); err == nil {
		t.Error("expected an error for a duplicate id")
	}
	if _, err := NewRegistry(fakeCheck{""}); err == nil {
		t.Error("expected an error for an empty id")
	}
}

// Every check has wording, in the same order as the pack, and every
// finding and skip a check can return has a line in the pack.
func TestEveryCheckHasWording(t *testing.T) {
	p, err := packs.English()
	if err != nil {
		t.Fatal(err)
	}
	all := Default().All()
	if len(all) != p.TotalChecks {
		t.Fatalf("got %d checks, want all %d", len(all), p.TotalChecks)
	}
	for i, c := range all {
		w := p.Check(c.ID())
		if w == nil {
			t.Errorf("check %q has no wording in packs/checks/en.yaml", c.ID())
			continue
		}
		if p.Checks[i].ID != c.ID() {
			t.Errorf("check %d is %q in the code and %q in the pack", i, c.ID(), p.Checks[i].ID)
		}
	}
	for id, keys := range findingKeys {
		w := p.Check(id)
		for _, k := range keys {
			if _, ok := w.Findings[k]; !ok {
				t.Errorf("check %q returns finding %q, which has no wording", id, k)
			}
		}
	}
	for id, keys := range skipKeys {
		w := p.Check(id)
		for _, k := range keys {
			if w.Skips[k] == "" && p.Skips[k] == "" {
				t.Errorf("check %q can skip with %q, which has no wording", id, k)
			}
		}
	}
}

// findingKeys and skipKeys list what each check can return.
var findingKeys = map[string][]string{
	"load": {"high"}, "memory": {"high", "no-swap"},
	"disk":              {"space-warning", "space-critical", "inodes-warning", "inodes-critical"},
	"containers":        {"exited", "unhealthy", "restarts"},
	"oom":               {"killed", "killed-no-swap"},
	"certificates":      {"expiring", "expired"},
	"backups":           {"not-set", "empty", "old"},
	"updates":           {"waiting"},
	"open-ports":        {"open"},
	"exposed-databases": {"open"},
	"docker-firewall":   {"bypass"},
	"ssh":               {"password", "root"},
	"firewall":          {"off"},
	"login-protection":  {"missing"},
	"secrets-in-files":  {"world-readable", "in-compose", "in-history"},
	"risky-containers":  {"privileged", "docker-socket", "root"},
	"vulnerabilities":   {"system", "image"},
	"break-in": {"changed-program", "temp-program", "miner", "autostart-temp", "autostart-download",
		"extra-root", "preload", "history-off", "auth-log-empty", "new-account", "new-key"},
	"server-location":      {"outside"},
	"database-connections": {"outside"},
	"backup-destinations":  {"outside"},
	"payment-data":         {"outside"},
}

var skipKeys = map[string][]string{
	"load": {"not-linux", "failed"}, "memory": {"not-linux", "failed"}, "disk": {"not-linux", "failed"},
	"containers": {"needs-root", "failed"}, "oom": {"needs-root", "failed", "no-kernel-log"},
	"certificates": {"needs-root"}, "backups": {"needs-root", "failed"}, "updates": {"no-apt", "failed"},
	"open-ports": {"not-linux"}, "exposed-databases": {"not-linux", "needs-root", "failed"},
	"docker-firewall": {"needs-root", "failed"}, "firewall": {"needs-root"},
	"secrets-in-files": {"needs-root", "failed"}, "risky-containers": {"needs-root", "failed"},
	"vulnerabilities": {"not-installed", "no-database", "bad-version", "failed", "needs-root"},
	"server-location": {"unknown", "failed"}, "database-connections": {"needs-root", "failed"},
	"backup-destinations": {"needs-root", "failed"}, "outside-services": {"needs-root"},
	"payment-data": {"failed"}, "break-in": {"needs-root"},
}
