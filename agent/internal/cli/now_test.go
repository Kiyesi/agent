package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKiyesiAloneShowsWhatNeedsYouAndTheNextCommand(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"NEEDS YOU NOW",
		// The fake API's INC-12 is acknowledged, so it is listed without "Nobody has acknowledged it".
		"INC-12 is open: checkout-api-prod answering with server errors.\n      kiyesi incident INC-12",
		"Shop is not answering.\n      kiyesi uptime",
		"checkout-api-prod has 2 critical findings.\n      kiyesi findings checkout-api-prod",
		"\nNext: kiyesi incident ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "--json")
	var r nowResult
	if code != ExitOK || json.Unmarshal([]byte(out), &r) != nil || len(r.Items) == 0 || r.Next == "" || r.Servers != 2 {
		t.Errorf("json: %d %s", code, out)
	}
}

func TestKiyesiAloneWhenNotSignedInPointsToScanAndLogin(t *testing.T) {
	t.Setenv("KIYESI_CONFIG", t.TempDir())
	keychain = noKeychain{}
	code, out, _ := runCLI(t)
	if code != ExitOK || !strings.Contains(out, "sudo kiyesi scan") || !strings.Contains(out, "kiyesi login") {
		t.Errorf("%d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "nonsense"); code != ExitUsage || !strings.Contains(errOut, "unknown command") {
		t.Errorf("a typo must not run kiyesi alone: %d %q", code, errOut)
	}
}

func TestFindingsListsEachProblemWithItsFix(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "findings", "--severity", "critical")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if q := lastLogs(); q.Get("severity") != "critical" {
		t.Errorf("query = %v", q)
	}
	for _, want := range []string{
		"CRITICAL  Redis is open to the internet on port 6379 · likely",
		"checkout-api-prod · Exposed databases",
		"Fix:\n            bind the port to 127.0.0.1 in docker-compose.yml, then\n            docker compose up -d redis",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, out, _ := runCLI(t, "findings", "new-box"); code != ExitOK || !strings.Contains(out, "new-box has not sent a scan yet, so there are no findings yet.") {
		t.Errorf("another server: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "findings", "nope"); code != ExitUsage || !strings.Contains(errOut, "kiyesi servers") {
		t.Errorf("unknown server: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "findings", "--severity", "bad"); code != ExitUsage || !strings.Contains(errOut, "critical, warning or info") {
		t.Errorf("bad severity: %d %q", code, errOut)
	}
}

func TestProjectAndEnvNarrowAnyList(t *testing.T) {
	signInForTest(t)
	if code, _, errOut := runCLI(t, "servers", "--project", "Shop", "--env", "production"); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if f := getLastFilter(); f != [2]string{"Shop", "production"} {
		t.Errorf("servers sent %v", f)
	}
	if code, _, _ := runCLI(t, "incidents", "--env", "staging"); code != ExitOK || getLastFilter() != [2]string{"", "staging"} {
		t.Errorf("incidents sent %v", getLastFilter())
	}
	// Without the flags, nothing is narrowed, even after a narrowed command.
	runCLI(t, "servers")
	if f := getLastFilter(); f != [2]string{"", ""} {
		t.Errorf("unfiltered sent %v", f)
	}
}

func TestOpenPrintsAndOpensTheMatchingPage(t *testing.T) {
	signInForTest(t)
	var opened string
	openBrowser = func(u string) { opened = u }
	t.Setenv("KIYESI_DASHBOARD", "https://app.example.test")
	for args, want := range map[string]string{
		"open INC-12":            "https://app.example.test/incident/?id=INC-12",
		"open 12":                "https://app.example.test/incident/?id=INC-12",
		"open checkout-api-prod": "https://app.example.test/server/?id=s1",
		"open logs":              "https://app.example.test/logs/",
		"open":                   "https://app.example.test/",
		"credit topup":           "https://app.example.test/credit/",
	} {
		code, out, errOut := runCLI(t, strings.Fields(args)...)
		if code != ExitOK || strings.TrimSpace(out) != want || opened != want {
			t.Errorf("%s: %d %q %q opened %q", args, code, out, errOut, opened)
		}
	}
	if code, _, errOut := runCLI(t, "open", "nothing-here"); code != ExitUsage || !strings.Contains(errOut, "INC-12") {
		t.Errorf("unknown: %d %q", code, errOut)
	}
	// With a team chosen, the address names it, so the dashboard shows that team.
	if code, _, _ := runCLI(t, "team", "use", "Globex"); code != ExitOK {
		t.Fatalf("team use: %d", code)
	}
	for args, want := range map[string]string{
		"open INC-12": "https://app.example.test/incident/?id=INC-12&team=bbbbbbbbbbbbbbbbbbbbbbbb",
		"open logs":   "https://app.example.test/logs/?team=bbbbbbbbbbbbbbbbbbbbbbbb",
		"open":        "https://app.example.test/?team=bbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		if code, out, _ := runCLI(t, strings.Fields(args)...); code != ExitOK || strings.TrimSpace(out) != want || opened != want {
			t.Errorf("%s: %d %q opened %q", args, code, out, opened)
		}
	}
}

func TestDashboardIsBesideTheAPI(t *testing.T) {
	for api, want := range map[string]string{
		"https://api.kiyesi.dev":   "https://app.kiyesi.dev",
		"https://api.example.com/": "https://app.example.com",
		"http://localhost:8080":    "http://localhost:8080",
	} {
		if got := dashboardURL(api); got != want {
			t.Errorf("%s: %s", api, got)
		}
	}
}

func TestKiyesiAloneShowsTheTeamsCalmStreakWhenThereIsOne(t *testing.T) {
	var b strings.Builder
	days := 6
	printNow(&b, nowResult{Servers: 2, Next: "kiyesi servers", CalmDays: &days})
	if !strings.Contains(b.String(), "Calm streak: 6 days without a critical finding on any server.") {
		t.Errorf("got:\n%s", b.String())
	}
	b.Reset()
	open := 0
	printNow(&b, nowResult{Servers: 2, Next: "kiyesi servers", CalmDays: &open})
	if strings.Contains(b.String(), "Calm streak") {
		t.Errorf("a critical finding is open, so no streak to show:\n%s", b.String())
	}
}
