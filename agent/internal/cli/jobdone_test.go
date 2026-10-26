package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/jobs"
)

// kiyesi job done records a run the job made on its own, with its exit code
// and length, and starts nothing; a bad name or a missing --exit says how.
func TestJobDoneRecordsARunAndStartsNothing(t *testing.T) {
	state := t.TempDir()
	t.Setenv("KIYESI_STATE", state)
	spool := filepath.Join(state, "runs")
	if err := os.MkdirAll(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "job", "done", "--name", "nightly-backup", "--exit", "3", "--started", "1791000000")
	if code != ExitOK || out != "" {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	runs := jobs.Take(spool)
	if len(runs) != 1 || runs[0].Name != "nightly-backup" || *runs[0].ExitCode != 3 || runs[0].StartedAt != "2026-10-03T04:00:00Z" {
		t.Fatalf("runs = %+v", runs)
	}
	for _, args := range [][]string{
		{"job", "done", "--name", "bad name!", "--exit", "0"},
		{"job", "done", "--name", "nightly-backup"},
		{"job", "done", "--name", "nightly-backup", "--exit", "0", "--started", "yesterday"},
	} {
		if code, _, errOut := runCLI(t, args...); code != ExitUsage || errOut == "" {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if code, _, errOut := runCLI(t, "run"); code != ExitUsage || !strings.Contains(errOut, `unknown command "run"`) {
		t.Errorf("kiyesi run should be gone: %d %q", code, errOut)
	}
}

// kiyesi job start records only a start, for the service to join to the
// done that follows; it starts nothing.
func TestJobStartRecordsAStart(t *testing.T) {
	state := t.TempDir()
	t.Setenv("KIYESI_STATE", state)
	spool := filepath.Join(state, "runs")
	if err := os.MkdirAll(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI(t, "job", "start", "--name", "nightly-backup"); code != ExitOK || out != "" {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	runs := jobs.Take(spool)
	if len(runs) != 1 || runs[0].Name != "nightly-backup" || runs[0].EndedAt != "" || runs[0].ExitCode != nil {
		t.Fatalf("runs = %+v", runs)
	}
	if code, _, _ := runCLI(t, "job", "start"); code != ExitUsage {
		t.Errorf("no name: %d", code)
	}
}
