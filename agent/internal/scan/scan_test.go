package scan

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func TestLetter(t *testing.T) {
	for score, want := range map[int]string{100: "A", 90: "A", 89: "B", 75: "B", 74: "C", 60: "C", 59: "D", 55: "D", 40: "D", 39: "F", 0: "F"} {
		if got := Letter(score); got != want {
			t.Errorf("Letter(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestGradeMatchesThePRDExample(t *testing.T) {
	cs := []CheckResult{
		{Status: "fail", Findings: []Finding{{Severity: "critical"}}},
		{Status: "fail", Findings: []Finding{{Severity: "critical"}}},
		{Status: "fail", Findings: []Finding{{Severity: "warning"}, {Severity: "warning"}}},
		{Status: "fail", Findings: []Finding{{Severity: "warning"}}},
		{Status: "pass"}, {Status: "pass"},
		{Status: "skip"},
	}
	c, g := grade(cs, 22)
	if g.Score != 55 || g.Letter != "D" {
		t.Errorf("grade = %+v, want D 55", g)
	}
	if c.Critical != 2 || c.Warnings != 3 || c.Passed != 2 || c.Skipped != 1 || g.BasedOn != 6 || g.Total != 22 {
		t.Errorf("counts = %+v, grade = %+v", c, g)
	}
	if _, g := grade([]CheckResult{{Status: "fail", Findings: make([]Finding, 9)}}, 22); g.Score != 100 {
		t.Errorf("info-only findings must not cost points: %+v", g)
	}
	many := make([]Finding, 8)
	for i := range many {
		many[i].Severity = "critical"
	}
	if _, g := grade([]CheckResult{{Status: "fail", Findings: many}}, 22); g.Score != 0 || g.Letter != "F" {
		t.Errorf("the score must not go below 0: %+v", g)
	}
}

type panicCheck struct{}

func (panicCheck) ID() string { return "load" }
func (panicCheck) Run(context.Context, *checks.Env) checks.Result {
	panic("boom")
}

type slowCheck struct{}

func (slowCheck) ID() string { return "memory" }
func (slowCheck) Run(ctx context.Context, _ *checks.Env) checks.Result {
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond)
	return checks.Pass(nil)
}

func TestACrashOrHangIsSkippedNotPassed(t *testing.T) {
	old := DefaultTimeout
	DefaultTimeout = 50 * time.Millisecond
	defer func() { DefaultTimeout = old }()

	pack, err := packs.English()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := checks.NewRegistry(panicCheck{}, slowCheck{})
	if err != nil {
		t.Fatal(err)
	}
	sys := &system.System{FS: fstest.MapFS{}, Now: time.Now, Hostname: "h", OS: system.OSInfo{Name: "Ubuntu 24.04", Tested: true}}
	r := Run(context.Background(), checks.NewEnv(sys, config.Default()), reg, pack)
	if r.Checks[0].Status != "skip" || r.Checks[1].Status != "skip" || r.Counts.Passed != 0 || r.Counts.Skipped != 2 {
		t.Errorf("checks = %+v", r.Checks)
	}
	if r.Checks[1].SkipReason != "took too long and was stopped" {
		t.Errorf("timeout reason = %q", r.Checks[1].SkipReason)
	}
	if r.Grade.BasedOn != 0 {
		t.Errorf("based on = %d", r.Grade.BasedOn)
	}
}
