package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// The case from a real server: one fix Kiyesi makes, and root login left to
// the person signed in as root. Only what Kiyesi does is numbered.
func TestFixListNumbersOnlyWhatKiyesiDoes(t *testing.T) {
	fixers := map[string]fix.Fixer{}
	for _, f := range fix.All() {
		fixers[f.Name()] = f
	}
	r := scan.Report{}
	r.Grade.Letter, r.Grade.Score = "F", 25
	list := []*planned{
		{fixer: fixers["ssh-root"], findings: []scan.Finding{{Severity: "warning", Sentence: "SSH allows root login"}},
			plan: fix.Plan{Refuse: "You are signed in as root, so turning root login off could lock you out."}},
		{fixer: fixers["secret-files"], findings: []scan.Finding{{Severity: "warning", Sentence: "/opt/appstack/.env.api holds secrets and every user on this server can read it"}},
			plan: fix.Plan{Say: "Makes 1 file unreadable to other users on this server; its owner and group keep access: /opt/appstack/.env.api."}},
	}
	var b bytes.Buffer
	printPlan(render.NewWriter(&b, []string{"NO_COLOR=1"}), r, list, nil)
	out := b.String()
	for _, want := range []string{
		"Kiyesi can fix 1 thing for you:",
		"  1. /opt/appstack/.env.api holds secrets",
		"Left to you (1):",
		"  • SSH allows root login (ssh-root)  +5, to F 30, when done",
		"    You are signed in as root",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "2.") {
		t.Errorf("the item left to you is numbered:\n%s", out)
	}
	if strings.Index(out, "1. /opt") > strings.Index(out, "Left to you") {
		t.Errorf("what Kiyesi does should come first:\n%s", out)
	}
}

func TestGradeMoveReadsEvenly(t *testing.T) {
	var b bytes.Buffer
	w := render.NewWriter(&b, []string{"NO_COLOR=1"})
	for _, c := range []struct {
		bl   string
		bs   int
		al   string
		as   int
		want string
	}{
		{"F", 25, "F", 35, "GRADE  F 25 → F 35/100  +10"},
		{"B", 85, "A", 95, "GRADE  B 85 → A 95/100  +10 🎉"},
		{"A", 95, "B", 80, "GRADE  A 95 → B 80/100  −15"},
		{"A", 90, "A", 95, "GRADE  A 90 → A 95/100  +5"},
		{"A", 95, "A", 100, "GRADE  A 95 → A 100/100  +5 🎉"},
	} {
		b.Reset()
		_, _ = w.Write([]byte(render.GradeMove(c.bl, c.bs, c.al, c.as)))
		if got := b.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

// A whole plan as a person reads it, kept as a snapshot: what Kiyesi does,
// what is left to them, and what else costs points, so the grade adds up.
func TestFixPlanSnapshot(t *testing.T) {
	fixers := map[string]fix.Fixer{}
	for _, f := range fix.All() {
		fixers[f.Name()] = f
	}
	root := scan.Finding{Check: "ssh", Severity: "warning", Sentence: "SSH allows root login"}
	secret := scan.Finding{Check: "secrets-in-files", Severity: "warning", Sentence: "/opt/appstack/.env.api holds secrets and every user on this server can read it"}
	r := scan.Report{Checks: []scan.CheckResult{
		{ID: "ssh", Findings: []scan.Finding{root}},
		{ID: "secrets-in-files", Findings: []scan.Finding{secret}},
		{ID: "exposed-databases", Findings: []scan.Finding{{Check: "exposed-databases", Severity: "critical", Sentence: "Redis is open to the internet on port 6379"}}},
		{ID: "backups", Findings: []scan.Finding{{Check: "backups", Severity: "warning", Sentence: "No backup is set up for Kiyesi to check"}}},
		{ID: "break-in", Findings: []scan.Finding{{Check: "break-in", Severity: "info", Sentence: "root's login keys changed on 23 Oct 2026"}}},
	}}
	r.Grade.Letter, r.Grade.Score = "D", 50
	// The real refusal, as signed in as root with password login off.
	h := &cliHost{files: map[string][]byte{"/etc/ssh/sshd_config": []byte("Include /etc/ssh/sshd_config.d/*.conf\n")}}
	refusal := fixers["ssh-root"].Plan(context.Background(), h, fix.Input{User: "root"})
	if refusal.Refuse == "" {
		t.Fatalf("ssh-root as root was not refused: %+v", refusal)
	}
	list := []*planned{
		{fixer: fixers["ssh-root"], findings: []scan.Finding{root}, plan: refusal},
		{fixer: fixers["secret-files"], findings: []scan.Finding{secret}, plan: fix.Plan{Say: "Makes 1 file unreadable to other users on this server; its owner and group keep access: /opt/appstack/.env.api."}},
	}
	var b bytes.Buffer
	printPlan(render.NewWriter(&b, []string{"NO_COLOR=1"}), r, list, nil)
	snapshot(t, "fix-plan.txt", b.String())

	// Nothing Kiyesi can change: said plainly, and the rest still listed.
	b.Reset()
	printPlan(render.NewWriter(&b, []string{"NO_COLOR=1"}), r, list[:1], nil)
	snapshot(t, "fix-plan-none.txt", b.String())
}

func snapshot(t *testing.T, name, got string) {
	t.Helper()
	path := "testdata/" + name
	if *updateCommands {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/cli -run Snapshot -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs; if intended, run go test ./internal/cli -run Snapshot -update and review the diff.\n--- got ---\n%s", name, got)
	}
}

// Signed in as root, not through sudo, a scan by hand does not offer the
// root-login fix that kiyesi fix would refuse.
func TestScanAsRootDoesNotOfferRootLoginFix(t *testing.T) {
	testSystem(t)
	t.Setenv("SUDO_USER", "")
	old := scanAsRoot
	t.Cleanup(func() { scanAsRoot = old })
	scanAsRoot = func() bool { return true }
	base := newSystem
	newSystem = func(root bool, dir string) *system.System {
		s := base(root, dir)
		s.FS.(fstest.MapFS)["etc/ssh/sshd_config"] = &fstest.MapFile{Data: []byte("PasswordAuthentication no\nPermitRootLogin yes\n")}
		s.OS.ID = "ubuntu"
		return s
	}
	_, out, _ := runCLI(t, "scan", "--json")
	if strings.Contains(out, `"auto_fix": "ssh-root"`) || !strings.Contains(out, "SSH allows root login") {
		t.Fatalf("root by hand: %s", out)
	}
	t.Setenv("SUDO_USER", "ada")
	_, out, _ = runCLI(t, "scan", "--json")
	if !strings.Contains(out, `"auto_fix": "ssh-root"`) {
		t.Fatalf("through sudo, the fix should be offered: %s", out)
	}
}
