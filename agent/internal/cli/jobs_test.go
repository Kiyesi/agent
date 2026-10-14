package cli

import (
	"strings"
	"testing"
)

func TestJobsListsEachJobAndItsRuns(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "jobs")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"nightly-backup", "Every day at 04:00", "3 min 12 s", "MISSED", "send-order-emails", "48 s, usually 6 s", "on time"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	code, out, errOut = runCLI(t, "jobs", "nightly-backup")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"nightly-backup on checkout-db-prod: MISSED", "did not run when it was expected.", "exit code 2, 1 s", "pg_dump: error: connection refused"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "jobs", "nope"); code != ExitUsage || !strings.Contains(errOut, "no job called") {
		t.Errorf("unknown: %d %q", code, errOut)
	}
}
