package cli

import (
	"strings"
	"testing"
)

func TestPreflightSaysWaitWithReasonsAndExitsOne(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "preflight", "checkout-api-prod")
	if code != ExitFindings {
		t.Errorf("wait must exit 1, got %d", code)
	}
	if q := lastLogs(); q.Get("server") != "checkout-api-prod" {
		t.Errorf("query %v", q)
	}
	for _, want := range []string{
		"safe to deploy? · 6 checks\ncheckout-api-prod · Checkout · Production",
		// Reasons to wait come first.
		" WAIT  Memory         93% used. The app was killed at 10:41 today.\n WAIT  Backup",
		" PASS  Disk           64% used.",
		"ANSWER  WAIT  3 reasons",
		"DO FIRST\n 1. Add swap or move up a size",
		"exits with 0 for GO and 1 for WAIT",
		// How old the scan behind the answer is.
		"Last scan: ",
		"13 October 2026 10:00 UTC.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPreflightGoExitsZero(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "preflight", "calm-box")
	if code != ExitOK || !strings.Contains(out, "ANSWER  GO") {
		t.Errorf("%d:\n%s", code, out)
	}
	// No scan behind the answer: say so.
	if !strings.Contains(out, "No scan yet.") {
		t.Errorf("missing No scan yet:\n%s", out)
	}
}

func TestPreflightWithADeployTokenInCI(t *testing.T) {
	srv := signInForTest(t)
	code, out, errOut := runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=kdp_preflight"}, "preflight", "checkout-api-prod", "--api", srv.URL, "--json")
	if code != ExitFindings || !strings.Contains(out, `"answer": "wait"`) {
		t.Errorf("%d %s %s", code, out, errOut)
	}
	if code, _, errOut := runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=ksv_nope"}, "preflight", "x"); code != ExitUsage || !strings.Contains(errOut, "not a deploy token") {
		t.Errorf("%d %s", code, errOut)
	}
}

func TestPreflightNeedsAServerOffAConnectedServer(t *testing.T) {
	signInForTest(t)
	old := thisServer
	thisServer = func() agentConf { return agentConf{} }
	t.Cleanup(func() { thisServer = old })
	if code, _, errOut := runCLI(t, "preflight"); code != ExitUsage || !strings.Contains(errOut, "Name the server") {
		t.Errorf("%d %s", code, errOut)
	}
}
