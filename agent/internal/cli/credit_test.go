package cli

import (
	"strings"
	"testing"
)

func TestCreditShowsBalanceDaysLeftAndBundles(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "credit")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Balance: 120 server-days",
		"About 20 days left",
		"100 server-days for $15.00 (about $4.50 a server a month)",
		"6 servers on 12 October 2026",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
