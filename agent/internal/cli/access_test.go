package cli

import (
	"strings"
	"testing"
)

func TestWhoamiSaysRoleWhereAndUntil(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "whoami")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Frontend contractor in Acme.",
		"Where: Storefront, production only, except web-2.",
		"Until: 30 November 2026, then it stops by itself.",
		"Can act on: servers and findings, browser errors, incidents and assigned work.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Can see: servers and findings, metrics, logs") {
		t.Errorf("logs are hidden for this role:\n%s", out)
	}
}

func TestTeamRolesListsBuiltInAndMade(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "team", "roles")
	for _, want := range []string{"Owner", "built in", "Frontend contractor", "made from Member", "Client"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q (exit %d):\n%s", want, code, out)
		}
	}
}

func TestTeamAccessSetsRoleProjectsLeftOutAndEnd(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	code, out, errOut := runCLI(t, "team", "access", "amaka@example.com", "--role", "frontend contractor",
		"--projects", "Storefront", "--leave-out", "checkout-api-prod", "--until", "2026-11-30", "--code", "123456")
	if code != ExitOK || !strings.Contains(out, "Amaka Obi's access changed.") {
		t.Fatalf("access: %d %s %s", code, out, errOut)
	}
	want := `access {"endsAt":"2026-11-30","role":"6acc00000000000000000001","scope":{"all":false,"leftOut":["s1"],"projects":[{"environments":null,"projectId":"p1"}]},"twoStepCode":"123456"}`
	if len(serverCalls) != 1 || serverCalls[0] != want {
		t.Errorf("calls = %v", serverCalls)
	}
	if code, _, errOut := runCLI(t, "team", "access", "Amaka", "--role", "boss", "--code", "123456"); code != ExitUsage || !strings.Contains(errOut, "no role called") {
		t.Errorf("unknown role: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "team", "access", "Amaka", "--until", "30 Nov"); code != ExitUsage || !strings.Contains(errOut, "--until") {
		t.Errorf("bad day: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "team", "access", "Amaka", "--code", "000000"); code == ExitOK || !strings.Contains(errOut, "That code is not right") {
		t.Errorf("wrong code: %d %q", code, errOut)
	}
}

func TestTeamAccessKeepsWhereItAppliesWhenOnlyTheDayChanges(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	code, out, errOut := runCLI(t, "team", "access", "Amaka", "--until", "2026-12-31", "--code", "123456")
	if code != ExitOK {
		t.Fatalf("access: %d %s %s", code, out, errOut)
	}
	// Amaka sees one project in production only: that stays, never every project.
	want := `access {"endsAt":"2026-12-31","role":"member","scope":{"all":false,"projects":[{"environments":["production"],"projectId":"p2"}]},"twoStepCode":"123456"}`
	if len(serverCalls) != 1 || serverCalls[0] != want {
		t.Errorf("calls = %v", serverCalls)
	}
	if strings.Contains(out, "Where it applies changed") {
		t.Errorf("the scope did not change:\n%s", out)
	}
	// Naming projects changes it, and says so.
	serverCalls = nil
	code, out, _ = runCLI(t, "team", "access", "Amaka", "--projects", "Storefront", "--code", "123456")
	if code != ExitOK || !strings.Contains(out, "Where it applies changed too: only in Storefront.") {
		t.Errorf("projects: %d\n%s", code, out)
	}
}

func TestTeamUseChoosesWhichTeamCommandsAreFor(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "team", "use")
	if code != ExitOK || !strings.Contains(out, "* Acme (Owner)") || !strings.Contains(out, "  Globex (Viewer)") {
		t.Fatalf("list: %d\n%s", code, out)
	}
	if code, out, _ := runCLI(t, "team", "use", "globex"); code != ExitOK || !strings.Contains(out, "Now using Globex, as Viewer.") {
		t.Fatalf("use: %d %s", code, out)
	}
	// Every later command is for Globex.
	if _, out, _ := runCLI(t, "team", "use"); !strings.Contains(out, "* Globex (Viewer)") {
		t.Errorf("after use:\n%s", out)
	}
	if code, _, errOut := runCLI(t, "team", "use", "Initech"); code != ExitUsage || !strings.Contains(errOut, "Your teams: Acme, Globex") {
		t.Errorf("unknown: %d %q", code, errOut)
	}
}
