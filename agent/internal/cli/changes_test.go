package cli

import (
	"strings"
	"testing"
)

func TestProjectsRenameAndDeleteOnlyWhenEmpty(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	code, out, errOut := runCLI(t, "projects")
	if code != ExitOK || !strings.Contains(out, "Storefront") {
		t.Fatalf("list: %d %s %s", code, out, errOut)
	}
	if code, out, _ = runCLI(t, "projects", "rename", "storefront", "Shop front"); code != ExitOK || !strings.Contains(out, "Renamed Storefront to Shop front.") {
		t.Errorf("rename: %d %s", code, out)
	}
	code, out, errOut = runCLI(t, "projects", "delete", "Storefront")
	if code != ExitUsage || !strings.Contains(out, "2 servers") || !strings.Contains(out, "1 uptime check") || !strings.Contains(errOut, "nothing was deleted") {
		t.Errorf("delete in use: %d %s %s", code, out, errOut)
	}
	if code, out, _ = runCLI(t, "projects", "delete", "Demo client"); code != ExitOK || !strings.Contains(out, "Deleted the project Demo client.") {
		t.Errorf("delete empty: %d %s", code, out)
	}
	want := []string{"rename p1 Shop front", "delete project p2"}
	if strings.Join(serverCalls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", serverCalls)
	}
}

func TestProjectsRenameSaysWhatItNeedsWithoutSettings(t *testing.T) {
	signInForTest(t)
	if code, _, _ := runCLI(t, "team", "use", "Globex"); code != ExitOK {
		t.Fatal("team use")
	}
	for _, args := range [][]string{{"projects", "rename", "Storefront", "Shop"}, {"projects", "delete", "Demo client"}} {
		code, _, errOut := runCLI(t, args...)
		if code != ExitNoAccess || !strings.Contains(errOut, "Renaming or deleting projects needs Manage on settings") || strings.Contains(errOut, "Not found") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

func TestTeamLeaveNamesTheTeamAndForgetsIt(t *testing.T) {
	signInForTest(t)
	if code, _, _ := runCLI(t, "team", "use", "Globex"); code != ExitOK {
		t.Fatal("team use")
	}
	code, out, errOut := runCLIInput(t, "no\n", "team", "leave")
	if code != ExitUsage || !strings.Contains(out+errOut, "Leave Globex?") {
		t.Errorf("ask: %d %q %q", code, out, errOut)
	}
	if code, out, _ := runCLI(t, "team", "leave", "--yes"); code != ExitOK || !strings.Contains(out, "You left Globex.") {
		t.Errorf("leave: %d %s", code, out)
	}
	if l, err := loadLogin(); err != nil || l.Team != "" {
		t.Errorf("the left team must be forgotten here: %+v %v", l, err)
	}
}

func TestSessionsSayWhatTheyKnow(t *testing.T) {
	signInForTest(t)
	// The date is when the session was last refreshed, not its last use.
	if code, out, _ := runCLI(t, "sessions"); code != ExitOK || !strings.Contains(out, "LAST REFRESHED") || strings.Contains(out, "LAST USED") {
		t.Errorf("sessions: %d\n%s", code, out)
	}
	if code, _, _ := runCLI(t, "team", "use", "Globex"); code != ExitOK {
		t.Fatal("team use")
	}
	// Nothing else to end: say so, never "0 sessions".
	if code, out, _ := runCLI(t, "sessions", "end", "--others"); code != ExitOK || strings.TrimSpace(out) != "No other sessions." {
		t.Errorf("end others: %d %q", code, out)
	}
}

func TestUptimeEditServersRenameAndDeploysRemove(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	if code, out, errOut := runCLI(t, "uptime", "edit", "shop", "--address", "https://shop.example.com/health", "--project", "Storefront"); code != ExitOK || !strings.Contains(out, "Its history stays") {
		t.Fatalf("edit: %d %s %s", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, "uptime", "edit", "Shop"); code != ExitUsage || !strings.Contains(errOut, "say what to change") {
		t.Errorf("edit nothing: %d %s", code, errOut)
	}
	if code, out, _ := runCLI(t, "servers", "rename", "checkout-api-prod", "checkout-web"); code != ExitOK || !strings.Contains(out, "Renamed checkout-api-prod to checkout-web.") {
		t.Errorf("rename: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "servers", "rename", "checkout-api-prod", "web 2"); code != ExitUsage || !strings.Contains(errOut, "letters, digits") {
		t.Errorf("bad name: %d %s", code, errOut)
	}
	if code, out, errOut := runCLI(t, "deploys", "remove", "checkout-api", "3.8.1"); code != ExitOK || !strings.Contains(out, "Removed the deploy checkout-api 3.8.1") {
		t.Errorf("remove deploy: %d %s %s", code, out, errOut)
	}
	if code, _, _ := runCLI(t, "deploys", "remove", "checkout-api", "0.0.0"); code != ExitUsage {
		t.Errorf("remove unknown deploy: %d", code)
	}
	want := []string{
		`edit u1 {"projectId":"p1","url":"https://shop.example.com/health"}`,
		"rename s1 checkout-web",
		"remove deploy d1",
	}
	if strings.Join(serverCalls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", serverCalls)
	}
}

func TestTeamLeaveAndSessions(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	if code, out, _ := runCLI(t, "team", "leave", "--yes"); code != ExitOK || !strings.Contains(out, "You left Acme.") {
		t.Errorf("leave: %d %s", code, out)
	}
	code, out, _ := runCLI(t, "sessions")
	if code != ExitOK || !strings.Contains(out, "Chrome on macOS (this one)") || !strings.Contains(out, "The kiyesi command") {
		t.Errorf("sessions: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "sessions", "end", "1"); code != ExitUsage || !strings.Contains(errOut, "kiyesi logout") {
		t.Errorf("end this one: %d %s", code, errOut)
	}
	if code, out, _ := runCLI(t, "sessions", "end", "2"); code != ExitOK || !strings.Contains(out, "Signed out The kiyesi command.") {
		t.Errorf("end 2: %d %s", code, out)
	}
	if code, out, _ := runCLI(t, "sessions", "end", "--others"); code != ExitOK || !strings.Contains(out, "1 session") {
		t.Errorf("end others: %d %s", code, out)
	}
	want := []string{"leave", "end se2", "end others"}
	if strings.Join(serverCalls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", serverCalls)
	}
}
