package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogsSearchesWithTheGivenFilters(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "logs", "--server", "checkout-api-prod", "--level", "errors", "--since", "24h", "--search", "heap limit", "--source", "checkout-api")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	q := lastLogs()
	if q.Get("server") != "s1" || q.Get("level") != "error" || q.Get("range") != "24h" || q.Get("q") != "heap limit" || q.Get("source") != "checkout-api" || q.Get("since") != "" {
		t.Errorf("query = %v", q)
	}
	// Oldest first, with the level and the source; one server, so no server name.
	warn := strings.Index(out, "WARN   checkout-api  Heap usage at 91% of the limit")
	fatal := strings.Index(out, "ERROR  checkout-api  FATAL ERROR: Reached heap limit")
	if warn < 0 || fatal < warn {
		t.Errorf("out:\n%s", out)
	}
	for _, want := range []string{"over today's log allowance", "Showing the newest 2 lines"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("missing %q in %q", want, errOut)
		}
	}
	// Every server: each line says which.
	_, out, _ = runCLI(t, "logs")
	if !strings.Contains(out, "checkout-api-prod checkout-api  FATAL ERROR") {
		t.Errorf("all servers:\n%s", out)
	}
	for _, bad := range [][]string{
		{"logs", "--since", "forever"},
		{"logs", "--level", "debug"},
		{"logs", "nope-server"},
		{"logs", "a", "--server", "b"},
		{"logs", "--limit", "5000"},
	} {
		if code, _, errOut := runCLI(t, bad...); code != ExitUsage || errOut == "" {
			t.Errorf("%v: exit %d %q", bad, code, errOut)
		}
	}
}

func TestLogsFollowPrintsEachNewLineOnce(t *testing.T) {
	signInForTest(t)
	old := followEvery
	followEvery = 10 * time.Millisecond
	t.Cleanup(func() { followEvery = old })
	followPolls.Store(0)
	code, out, errOut := runCLI(t, "logs", "checkout-api-prod", "-f")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if q := lastLogs(); q.Get("since") == "" || q.Get("server") != "s1" {
		t.Errorf("follow query = %v", q)
	}
	if strings.Count(out, "FATAL ERROR: Reached heap limit") != 1 {
		t.Errorf("a line was printed twice:\n%s", out)
	}
	for _, want := range []string{"new line 1", "new line 2"} {
		if strings.Count(out, want) != 1 {
			t.Errorf("want %q once:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "Press Ctrl+C to stop") {
		t.Errorf("err = %q", errOut)
	}
}

func TestLogsOutputSavesAFile(t *testing.T) {
	signInForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "checkout.jsonl")
	code, out, errOut := runCLI(t, "logs", "--server", "checkout-api-prod", "--since", "7d", "--level", "error", "--output", path)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	q := lastLogs()
	if q.Get("format") != "jsonl" || q.Get("server") != "s1" || q.Get("range") != "7d" || q.Get("level") != "error" {
		t.Errorf("query = %v", q)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "FATAL ERROR") {
		t.Errorf("file: %q %v", data, err)
	}
	if !strings.Contains(out, "Saved "+path) {
		t.Errorf("out = %q", out)
	}
	// Nothing half-written is left behind when the download is refused.
	bad := filepath.Join(dir, "other.txt")
	code, _, errOut = runCLI(t, "logs", "--server", "new-box", "--output", bad)
	if code == ExitOK || !strings.Contains(errOut, "does not allow downloading logs") {
		t.Errorf("refused: exit %d %q", code, errOut)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
	for _, bad := range [][]string{
		{"logs", "--output", filepath.Join(dir, "x.csv")},
		{"logs", "--output", filepath.Join(dir, "x.txt"), "--follow"},
	} {
		if code, _, errOut := runCLI(t, bad...); code != ExitUsage || errOut == "" {
			t.Errorf("%v: exit %d %q", bad, code, errOut)
		}
	}
}
