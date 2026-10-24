package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
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
	} {
		b.Reset()
		_, _ = w.Write([]byte(render.GradeMove(c.bl, c.bs, c.al, c.as)))
		if got := b.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}
