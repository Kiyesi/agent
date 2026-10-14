package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPassportPrintsEveryPart(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "passport", "checkout-api-prod")
	if code != ExitOK {
		t.Fatalf("%d %s", code, errOut)
	}
	for _, want := range []string{
		"Server passport: checkout-api-prod",
		"WHAT THIS SERVER IS FOR\n  Runs the checkout API for the Checkout project.",
		"docker compose restart checkout-api",
		"6379       SHOULD BE CLOSED   Redis is open to the internet on port 6379.",
		"renew-certificates       Every day at 03:00       Failed on its last run.",
		"Go back to the version before\n    IMAGE_TAG=3.8.0 docker compose up -d checkout-api",
		"Cost               USD 6 a month",
		"On call            Ifeoma Nwosu",
		"checkout-db-prod:5432",
		"checkout-api was killed for using too much memory.",
		"--share for a link that lasts 7 days",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "passport", "nope"); code != ExitUsage || !strings.Contains(errOut, "kiyesi servers") {
		t.Errorf("%d %s", code, errOut)
	}
}

func TestPassportPDFAndShareLink(t *testing.T) {
	signInForTest(t)
	dir := t.TempDir()
	old, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(old) })
	code, out, _ := runCLI(t, "passport", "checkout-api-prod", "--pdf")
	data, err := os.ReadFile(filepath.Join(dir, "passport-checkout-api-prod.pdf"))
	info, _ := os.Stat(filepath.Join(dir, "passport-checkout-api-prod.pdf"))
	if code != ExitOK || err != nil || string(data) != "%PDF-1.7 passport" || info.Mode().Perm() != 0o600 || !strings.Contains(out, "Saved passport-checkout-api-prod.pdf") {
		t.Errorf("pdf: %d %s %v", code, out, err)
	}
	code, out, _ = runCLI(t, "passport", "checkout-api-prod", "--share")
	if code != ExitOK || !strings.Contains(out, "https://reports.kiyesi.dev/r/abc\nRead-only, until 20 October 2026") {
		t.Errorf("share: %d %s", code, out)
	}
}
