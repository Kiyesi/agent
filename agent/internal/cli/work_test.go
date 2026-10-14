package cli

import (
	"strings"
	"testing"
)

func TestMineListsYoursThenNobodysWithShortRefs(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "mine")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Assigned to you (1)",
		"db-d00d01",
		"acknowledged",
		"Nobody owns yet (2)",
		"INC-11",
		"job-a7b8c9",
		"kiyesi assign <ref> <teammate>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "Assigned to you") > strings.Index(out, "Nobody owns yet") {
		t.Errorf("yours should come first:\n%s", out)
	}
}

func TestAssignSuggestsThenGivesByName(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "assign", "job-a7b8c9")
	if code != ExitOK || !strings.Contains(out, "Suggested: It is a job on a server, and Ifeoma Nwosu is on call.") ||
		!strings.Contains(out, "Not listed, as their access does not include it: Kemi Lawal") {
		t.Fatalf("suggest: %d\n%s", code, out)
	}
	serverCalls = nil
	code, out, errOut := runCLI(t, "assign", "job-a7b8c9", "ifeoma", "--note", "Disk was full last time")
	if code != ExitOK || !strings.Contains(out, "Gave job-a7b8c9 to Ifeoma Nwosu.") {
		t.Fatalf("assign: %d %s %s", code, out, errOut)
	}
	if len(serverCalls) != 1 || serverCalls[0] != "/v1/work/assign job:6ac9e0a1b2c3d4e5f6a7b8c9 u2 Disk was full last time" {
		t.Errorf("calls = %v", serverCalls)
	}
	// Two people share a first name: the full name is asked for.
	if code, _, errOut := runCLI(t, "assign", "INC-11", "obi"); code != ExitUsage || !strings.Contains(errOut, "cannot be given") {
		t.Errorf("surname alone: %d %q", code, errOut)
	}
	if code, out, _ := runCLI(t, "assign", "INC-11", "me"); code != ExitOK || !strings.Contains(out, "INC-11 is yours.") {
		t.Errorf("me: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "assign", "job-zzzzzz", "me"); code != ExitUsage || !strings.Contains(errOut, "Nothing open called job-zzzzzz") {
		t.Errorf("unknown: %d %q", code, errOut)
	}
}

func TestAckAndResolveWorkThatIsNotAnIncident(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	if code, out, errOut := runCLI(t, "ack", "job-a7b8c9"); code != ExitOK || !strings.Contains(out, "Acknowledged job-a7b8c9") {
		t.Fatalf("ack: %d %s %s", code, out, errOut)
	}
	if code, out, errOut := runCLI(t, "resolve", "job-a7b8c9", "--note", "Freed space"); code != ExitOK || !strings.Contains(out, "Marked job-a7b8c9 fixed") {
		t.Fatalf("resolve: %d %s %s", code, out, errOut)
	}
	want := []string{
		"/v1/work/ack job:6ac9e0a1b2c3d4e5f6a7b8c9 <nil> <nil>",
		"/v1/work/fix job:6ac9e0a1b2c3d4e5f6a7b8c9 <nil> Freed space",
	}
	if strings.Join(serverCalls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", serverCalls)
	}
}

func TestTeamInviteAndActivity(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "team")
	for _, want := range []string{"Ada Obi (you)", "Owner", "DevOps", "Telegram: Ada", "Amaka Obi", "Checkout", "seun@example.com", "invited, not joined yet"} {
		if !strings.Contains(out, want) {
			t.Errorf("team: missing %q (exit %d):\n%s", want, code, out)
		}
	}
	serverCalls = nil
	code, out, errOut := runCLI(t, "team", "invite", "kemi@example.com", "--role", "viewer", "--area", "frontend")
	if code != ExitOK || !strings.Contains(out, "https://app.kiyesi.dev/join/?invite=abc") {
		t.Fatalf("invite: %d %s %s", code, out, errOut)
	}
	if serverCalls[0] != "invite kemi@example.com viewer frontend" {
		t.Errorf("calls = %v", serverCalls)
	}
	if code, _, errOut := runCLI(t, "team", "invite", "x@example.com", "--role", "boss"); code != ExitUsage || !strings.Contains(errOut, "--role") {
		t.Errorf("bad role: %d %q", code, errOut)
	}
	code, out, _ = runCLI(t, "activity", "--limit", "10")
	if code != ExitOK || !strings.Contains(out, "Ada Obi") || !strings.Contains(out, "Escalated INC-12 to Ifeoma Nwosu") || !strings.Contains(out, "Kiyesi") {
		t.Fatalf("activity: %d\n%s", code, out)
	}
	if lastLogs().Get("limit") != "10" {
		t.Errorf("limit = %v", lastLogs())
	}
}
