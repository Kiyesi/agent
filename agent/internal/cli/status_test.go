package cli

import (
	"strings"
	"testing"
)

func TestStatusListsPagesAndWhatEachShows(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "status")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Acme status (public), https://status.kiyesi.dev/acme-status",
		"3 email subscribers, 41 views this week",
		"Placing orders: HAVING PROBLEMS",
		"Payment page: working normally",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestStatusPostAddsToTheOpenProblem(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	code, out, errOut := runCLI(t, "status", "post", "We found the cause.", "--state", "fixing")
	if code != ExitOK || !strings.Contains(out, "Posted on https://status.kiyesi.dev/acme-status: Some orders are failing (fixing)") {
		t.Fatalf("post: %d %s %s", code, out, errOut)
	}
	want := `status {"postId":"p1","state":"fixing","text":"We found the cause."}`
	if len(serverCalls) != 1 || serverCalls[0] != want {
		t.Errorf("calls = %v", serverCalls)
	}
	code, _, errOut = runCLI(t, "status", "post", "x", "--state", "broken")
	if code != ExitUsage || !strings.Contains(errOut, "--state must be one of") {
		t.Errorf("bad state: %d %s", code, errOut)
	}
}
