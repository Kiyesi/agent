package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabasesAndCosts(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "databases")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"orders", "PostgreSQL 15.4", "21.5 GB of 25 GB", "61 of 100", "14", "NEEDS ATTENTION", "hosted (read from checkout-api-prod)", "412 MB of 512 MB", "orders: At the rate it grew, storage is full in about 9 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("databases: missing %q in:\n%s", want, out)
		}
	}
	code, out, errOut = runCLI(t, "costs")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"Servers, each month: USD 54. You could save USD 24 a month.", "1 GB, 1 CPU", "TOO SMALL", "larger than needed", "not set", "too early", "tools-01: 4 GB is enough, even at its busiest"} {
		if !strings.Contains(out, want) {
			t.Errorf("costs: missing %q in:\n%s", want, out)
		}
	}
}

func TestDatabasesCheckReadsTheSettings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(p, []byte("databases:\n  - name: orders\n    url: ftp://nope\n  - name: shop\n    url: postgres://ro:pw@127.0.0.1:1/shop\n    limit: lots\n"), 0o600)
	code, out, _ := runCLI(t, "databases", "check", "--config", p)
	if code != ExitFindings {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{"orders: The address is not one Kiyesi reads", `shop: "LOTS" is not a size: write it as 512MB or 25GB`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	empty := filepath.Join(dir, "empty.yaml")
	_ = os.WriteFile(empty, []byte("home_country: NG\n"), 0o600)
	if code, out, _ := runCLI(t, "databases", "check", "--config", empty); code != ExitOK || !strings.Contains(out, "No databases in") {
		t.Errorf("empty: %d %s", code, out)
	}
}

func TestCostsInAnyCurrencyWithTheRateWarning(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "costs", "--currency", "ngn")
	if code != ExitOK {
		t.Fatalf("%d %s", code, errOut)
	}
	if q := lastLogs(); q.Get("currency") != "NGN" {
		t.Errorf("query %v", q)
	}
	for _, want := range []string{
		"WARNING  The exchange rate moved your monthly server bill up 8.0% since 2026-09-14,\n         from NGN 77500 to NGN 83700, with no change to your servers.",
		"Servers, each month: NGN 83700. You could save NGN 37200 a month.",
		"As billed: USD 54. At the rate of 2026-10-13, from open.er-api.com.",
		"USD 6 (NGN 9300)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "costs", "--currency", "naira"); code != ExitUsage || !strings.Contains(errOut, "three letters") {
		t.Errorf("%d %s", code, errOut)
	}
}
