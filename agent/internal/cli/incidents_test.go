package cli

import (
	"strings"
	"testing"
)

func TestIncidentsListsSourceAndStatus(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "incidents")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if q := lastLogs(); q.Get("status") != "open" {
		t.Errorf("query = %v", q)
	}
	for _, want := range []string{"INC-12", "Critical", "server, confirmed", "acknowledged", "INC-11", "frontend, confirmed", "kiyesi incident <id>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "incidents", "--status", "closed"); code != ExitUsage || !strings.Contains(errOut, "--status") {
		t.Errorf("bad status: %d %q", code, errOut)
	}
}

func TestIncidentShowsEvidenceTimelineAndFix(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "incident", "INC-11")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Likely source: frontend, confirmed",
		"Browser    214 errors on /checkout/payment since 09:09, all on version 2.14.0.   points here",
		"storefront-web 2.14.0 went out at 09:05.",
		"Your team's note from INC-4 (Tunde B.): Rolled back, added the missing check.",
		"Suggested fix: frontend error that starts right after a deploy",
		"IMAGE_TAG=2.13.4 docker compose up -d storefront-web",
		`kiyesi resolve INC-11 --note "what fixed it"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "incident", "INC-99"); code != ExitUsage || !strings.Contains(errOut, "No incident with that number") {
		t.Errorf("unknown: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "incident", "checkout"); code != ExitUsage || !strings.Contains(errOut, "such as INC-12") {
		t.Errorf("bad ref: %d %q", code, errOut)
	}
}

func TestAckAndResolveAnIncidentFromTheTerminal(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	if code, out, errOut := runCLI(t, "ack", "INC-11"); code != ExitOK || !strings.Contains(out, "Acknowledged INC-11") {
		t.Fatalf("ack: %d %s %s", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, "resolve", "INC-11"); code != ExitUsage || !strings.Contains(errOut, "--note") {
		t.Errorf("no note: %d %q", code, errOut)
	}
	if code, out, errOut := runCLI(t, "resolve", "INC-11", "--note", "Rolled back to 2.13.4"); code != ExitOK || !strings.Contains(out, "Marked INC-11 fixed") {
		t.Fatalf("resolve: %d %s %s", code, out, errOut)
	}
	if got := strings.Join(serverCalls, "|"); got != "ack INC-11|fix INC-11 Rolled back to 2.13.4" {
		t.Errorf("calls = %q", got)
	}
}

func TestExplainPrintsTheParagraphForAClient(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "explain", "INC-11")
	if code != ExitOK || out != "This morning at 09:09, some pages did not work in customers' browsers. The fault is in an update to the website itself.\n" {
		t.Errorf("%d %q", code, out)
	}
	code, out, _ = runCLI(t, "explain", "INC-11", "--json")
	if code != ExitOK || !strings.Contains(out, `"paragraph": "This morning`) {
		t.Errorf("json: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "explain", "INC-99"); code != ExitUsage || !strings.Contains(errOut, "No incident with that number") {
		t.Errorf("%d %s", code, errOut)
	}
}
