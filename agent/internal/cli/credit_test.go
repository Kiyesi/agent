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

func TestCreditShowsBundlesOnlyToSomeoneWhoCanBuyThem(t *testing.T) {
	signInForTest(t)
	t.Cleanup(func() { creditBody = "" })
	opened := ""
	openBrowser = func(u string) { opened = u }
	for _, c := range []struct{ body, want string }{
		{`{"live":true,"selling":false,"canBuy":true,"balance":5,"daysLeft":null,"bundles":[{"credits":100,"usd":15,"perServerMonth":4.5}],"lines":[]}`, "Top-ups are not open yet."},
		{`{"live":true,"selling":true,"canBuy":false,"balance":5,"daysLeft":null,"bundles":[{"credits":100,"usd":15,"perServerMonth":4.5}],"lines":[]}`, "Ask an owner or someone with the Billing role to top up."},
	} {
		creditBody = c.body
		code, out, _ := runCLI(t, "credit")
		if code != ExitOK || !strings.Contains(out, c.want) || strings.Contains(out, "server-days for $") || strings.Contains(out, "Top up in the dashboard") {
			t.Errorf("exit %d, want %q and no bundles:\n%s", code, c.want, out)
		}
	}
	// topup does not open a page this person cannot pay on, and says who can.
	code, _, errOut := runCLI(t, "credit", "topup")
	if code != ExitNoAccess || !strings.Contains(errOut, "Billing role") || opened != "" {
		t.Errorf("topup without the right to buy: exit %d %q, opened %q", code, errOut, opened)
	}
	creditBody = ""
	if code, _, _ := runCLI(t, "credit", "topup"); code != ExitOK || !strings.HasSuffix(opened, "/credit/") {
		t.Errorf("topup: exit %d, opened %q", code, opened)
	}
}

func TestCreditSaysWhereTheTrialStands(t *testing.T) {
	signInForTest(t)
	t.Cleanup(func() { creditBody = "" })
	trial := `"trial":{"state":"active","serverName":"api-prod","endsAt":"2026-10-30T23:59:00Z","daysLeft":2}`
	for _, c := range []struct{ body, want, never string }{
		{`{"live":true,"selling":true,"canBuy":true,"balance":101,"daysLeft":null,"bundles":[],"lines":[],` + trial + `}`,
			"Your credit starts when the trial ends.", "Add credit before then"},
		{`{"live":true,"selling":true,"canBuy":true,"balance":0,"daysLeft":null,"state":{"storing":true},"bundles":[],"lines":[],` + trial + `}`,
			"Add credit before then to keep everything", "Your credit starts"},
	} {
		creditBody = c.body
		code, out, errOut := runCLI(t, "credit")
		if code != ExitOK {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		if !strings.Contains(out, "Trial: 2 days left on api-prod") || !strings.Contains(out, c.want) || strings.Contains(out, c.never) {
			t.Errorf("want %q and never %q:\n%s", c.want, c.never, out)
		}
	}
}
