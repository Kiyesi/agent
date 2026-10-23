package cli

import (
	"strings"
	"testing"
)

func TestCompareListsWhatDiffers(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "compare", "checkout-api-prod", "new-box")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"checkout-api-prod and new-box differ in 3 things.",
		"SECURITY (3 the same)", "SSH password login", "off", "on",
		"PACKAGES (412 the same)", "openssl", "3.0.13-0ubuntu3.1", "redis-server", "—",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SYSTEM") {
		t.Errorf("a section with nothing different is listed:\n%s", out)
	}
	if code, _, errOut := runCLI(t, "compare", "checkout-api-prod", "nope"); code != ExitUsage || !strings.Contains(errOut, `no server called "nope"`) {
		t.Errorf("unknown server: %d %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, "compare", "checkout-api-prod", "checkout-api-prod"); code != ExitUsage || !strings.Contains(errOut, "two different servers") {
		t.Errorf("same server: %d %s", code, errOut)
	}
	if code, out, _ := runCLI(t, "compare", "checkout-api-prod", "new-box", "--json"); code != ExitOK || !strings.Contains(out, `"differences": 3`) {
		t.Errorf("json: %d %s", code, out)
	}
}
