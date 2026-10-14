package cli

import (
	"strings"
	"testing"
)

func TestTracesListsSlowRequestsAndWhereTheTimeWent(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "traces", "--since", "1h", "--search", "/api/orders")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if q := lastLogs(); q.Get("filter") != "slow" || q.Get("range") != "1h" || q.Get("q") != "/api/orders" {
		t.Errorf("query = %v", q)
	}
	for _, want := range []string{
		"GET /api/orders/export", "8,470 ms", "Backend, 85% of the time", "req_2b77f0d3",
		"502", "Stopped at the web server", "kiyesi trace <id>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if _, _, _ = runCLI(t, "traces", "--all"); lastLogs().Get("filter") != "all" {
		t.Errorf("--all asked for %v", lastLogs())
	}
	if code, _, errOut := runCLI(t, "traces", "--since", "30d"); code != ExitUsage || !strings.Contains(errOut, "--since") {
		t.Errorf("bad since: %d %q", code, errOut)
	}
}

func TestTraceShowsEachStepAndHowItIsKnown(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "trace", "req_2b77f0d3")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"GET /api/orders/export   200   8,470 ms in total",
		"85% of this request was spent inside the backend",
		"Browser          ██████████████████████████████   8,470 ms   measured",
		"Database         ·█████························   1,200 ms   matched by time",
		"7,212 ms   worked out",
		"orders",
		// The web server's JSON line, as a summary.
		"checkout-api-prod · caddy  GET /api/orders/export → 200 · 8420 ms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "trace", "req_unknown1"); code != ExitUsage || !strings.Contains(errOut, "No request with that ID") {
		t.Errorf("unknown: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "trace", "bad id!"); code != ExitUsage || !strings.Contains(errOut, "not a request ID") {
		t.Errorf("bad id: %d %q", code, errOut)
	}
}
