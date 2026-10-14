package cli

import (
	"strings"
	"testing"
)

func TestDatamapListsEveryItemAndFlagsPaymentDataOutside(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "datamap")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Home country: Nigeria. 3 mapped, 2 outside, 1 payment data outside.",
		"orders:5432 (payment data)", "MUST MOVE", "managed", "set by you",
		"IP address data is powered by IPinfo.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	_, out, _ = runCLI(t, "datamap", "--outside")
	if strings.Contains(out, "storefront") || !strings.Contains(out, "orders:5432") {
		t.Errorf("--outside shows only what is outside:\n%s", out)
	}
}

func TestTipsAndAdvisoriesForAllOrOneServer(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "tips", "checkout-api-prod")
	if code != ExitOK || !strings.Contains(out, "checkout-api-prod: Set a memory limit on checkout-api") || !strings.Contains(out, "docker update --memory") {
		t.Errorf("tips: %d\n%s", code, out)
	}
	code, _, errOut := runCLI(t, "tips", "nope")
	if code != ExitUsage || !strings.Contains(errOut, `no server called "nope"`) {
		t.Errorf("unknown server: %d %s", code, errOut)
	}
	code, out, _ = runCLI(t, "advisories")
	if code != ExitOK || !strings.Contains(out, "[ACT SOON] checkout-api-prod: Ubuntu 20.04 on this server stopped getting security fixes") {
		t.Errorf("advisories: %d\n%s", code, out)
	}
}
