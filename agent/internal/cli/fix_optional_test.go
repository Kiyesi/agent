package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

// At A 100 with only an optional clean-up, kiyesi fix says nothing affects
// the grade, rather than "Kiyesi can fix 1 thing", which reads as a problem.
func TestFixCallsACleanUpOptional(t *testing.T) {
	r := scan.Report{Grade: scan.Grade{Score: 100, Letter: "A"}}
	list := []*planned{{
		fixer:    fix.ByName("docker-cleanup"),
		findings: []scan.Finding{{Severity: "info", Sentence: "Docker keeps 2.4 GB that nothing uses: old images and build cache"}},
		plan:     fix.Plan{Say: "Removes Docker images no container uses."},
	}}
	var b bytes.Buffer
	printPlan(&b, r, list, nil)
	got := b.String()
	if !strings.Contains(got, "Nothing affects the grade. 1 optional clean-up, if you want it:") || strings.Contains(got, "can fix") {
		t.Errorf("got:\n%s", got)
	}
	// With a warning in the list, it is a fix again.
	list[0].findings[0].Severity = "warning"
	b.Reset()
	printPlan(&b, r, list, nil)
	if !strings.Contains(b.String(), "Kiyesi can fix 1 thing for you:") {
		t.Errorf("got:\n%s", b.String())
	}
}

// The verb agrees with the count of findings left to a person.
func TestFixSaysHowManyNeedAPerson(t *testing.T) {
	for n, want := range map[int]string{1: "1 finding needs a person", 3: "3 findings need a person"} {
		var b bytes.Buffer
		printPlan(&b, scan.Report{Grade: scan.Grade{Score: 90, Letter: "A"}, Counts: scan.Counts{Warnings: n}}, nil, nil)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%d: %s", n, b.String())
		}
	}
}
