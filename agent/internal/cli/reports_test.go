package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportsListsWhatWasMade(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "reports")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"Checkout, August 2026", "(by Kiyesi)", "No incidents happened."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestReportMakesAMonthAndPrintsItsShareLink(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	pdf := filepath.Join(t.TempDir(), "checkout.pdf")
	code, out, errOut := runCLI(t, "report", "--project", "checkout", "--month", "2026-09", "--share", "7", "--pdf", pdf)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Checkout, September 2026",
		"Three incidents happened",
		"Share link, read-only until",
		"https://reports.kiyesi.dev/" + strings.Repeat("t", 43),
		"Saved " + pdf,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	want := []string{`report {"kind":"monthly","month":"2026-09","projectId":"pc"}`, "share r1 7"}
	if strings.Join(serverCalls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", serverCalls)
	}
	if data, _ := os.ReadFile(pdf); !strings.HasPrefix(string(data), "%PDF-") {
		t.Errorf("pdf = %q", data)
	}
}

func TestReportRefusesWhatCannotBeMade(t *testing.T) {
	signInForTest(t)
	for _, args := range [][]string{
		{"report", "--project", "Checkout", "--month", "September"},
		{"report", "--project", "Checkout", "--month", "2026-09", "--share", "5"},
		{"report", "--project", "Nowhere", "--month", "2026-09"},
	} {
		if code, _, _ := runCLI(t, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestReportCardCountsLastWeek(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "report", "card")
	if code != ExitOK || !strings.Contains(out, "Week of 5 October") || !strings.Contains(out, "typical time to fix 38 minutes") {
		t.Fatalf("card: %d %s %s", code, out, errOut)
	}
	// The help says when it is emailed, and that the free plan is not.
	_, help, _ := runCLI(t, "report", "card", "--help")
	if !strings.Contains(help, "08:00\nin their own time zone") || !strings.Contains(help, "free plan it is not emailed") {
		t.Errorf("help:\n%s", help)
	}
}

func TestDatamapReportSavesThePageWhenNoPDFCanBeMade(t *testing.T) {
	signInForTest(t)
	dir := t.TempDir()
	code, out, errOut := runCLI(t, "datamap", "--report", "--pdf", filepath.Join(dir, "map.pdf"))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "The PDF could not be made just now.") || !strings.Contains(out, "map.html instead") {
		t.Errorf("out:\n%s", out)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "map.html")); !strings.Contains(string(data), "Data map report") {
		t.Errorf("html = %q", data)
	}
}
