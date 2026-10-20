package cli

import (
	"strings"
	"testing"
)

func TestBadgePrintsTheLineToPasteAndTurnsOff(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "badge", "checkout-api-prod")
	if code != ExitOK {
		t.Fatalf("%d %s", code, errOut)
	}
	for _, want := range []string{
		"The grade badge of checkout-api-prod is on. Paste this into the README:",
		"[![Kiyesi grade](https://api.kiyesi.dev/v1/public/badge/AAAAAAAAAAAAAAAAAAAAAAAA.svg)](https://kiyesi.dev)",
		"Stop it with: kiyesi badge checkout-api-prod --off",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, out, _ := runCLI(t, "badge", "checkout-api-prod", "--off"); code != ExitOK || !strings.Contains(out, "stops answering now") {
		t.Errorf("off: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "badge", "new-box"); code != ExitNoAccess || !strings.Contains(errOut, "cannot manage") {
		t.Errorf("no access: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "badge", "nope"); code != ExitUsage || !strings.Contains(errOut, "kiyesi servers") {
		t.Errorf("unknown server: %d %q", code, errOut)
	}
	// Already off: say so, not that it stops now.
	if code, _, _ := runCLI(t, "team", "use", "Globex"); code != ExitOK {
		t.Fatal("team use")
	}
	if code, out, _ := runCLI(t, "badge", "checkout-api-prod", "--off"); code != ExitOK || !strings.Contains(out, "It was already off.") || strings.Contains(out, "stops answering now") {
		t.Errorf("already off: %d %s", code, out)
	}
}
