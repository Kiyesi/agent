package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kiyesi pullcheck: one change in on stdin, the findings out on stdout.
func TestPullcheckReadsStdinAndPrintsFindings(t *testing.T) {
	list := filepath.Join(t.TempDir(), "list.jsonl")
	if err := os.WriteFile(list, []byte(`{"sha":"abc","fetchedAt":"2026-11-10T09:00:00.000Z"}`+"\n"+`["MAL-2025-1","npm","left-pad-x",1,[],[]]`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/left-pad-x":{"version":"1.0.1","resolved":"https://registry.npmjs.org/left-pad-x/-/left-pad-x-1.0.1.tgz"}}}`
	in, _ := json.Marshal(map[string]any{
		"list": list, "rules": []string{"malicious"},
		"files": []map[string]any{{"path": "package-lock.json", "status": "added", "after": lock}},
	})
	code, out, errOut := runCLIInput(t, string(in), "pullcheck")
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	var got struct {
		Findings []struct {
			Rule    string   `json:"rule"`
			Reports []string `json:"reports"`
		} `json:"findings"`
		Languages     []string `json:"languages"`
		ListFetchedAt string   `json:"listFetchedAt"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if len(got.Findings) != 1 || got.Findings[0].Rule != "malicious" || got.Findings[0].Reports[0] != "MAL-2025-1" {
		t.Errorf("findings = %+v", got.Findings)
	}
	if got.ListFetchedAt != "2026-11-10T09:00:00Z" || len(got.Languages) != 1 {
		t.Errorf("listFetchedAt %q, languages %v", got.ListFetchedAt, got.Languages)
	}
}

// Input that is not valid: {"error": ...} on stdout and exit 2.
func TestPullcheckRefusesInvalidInput(t *testing.T) {
	for name, input := range map[string]string{
		"not JSON":       "{not json",
		"empty":          "",
		"unknown rule":   `{"rules":["everything"],"files":[]}`,
		"no path":        `{"rules":["hidden"],"files":[{"status":"added","patch":""}]}`,
		"unknown status": `{"rules":["hidden"],"files":[{"path":"a","status":"exploded"}]}`,
		"over 8 MB":      `{"files":[{"path":"a","patch":"` + strings.Repeat("a", 8<<20) + `"}]}`,
	} {
		code, out, _ := runCLIInput(t, input, "pullcheck")
		if code != ExitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, ExitUsage)
		}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(out), &e) != nil || e.Error == "" {
			t.Errorf("%s: stdout = %q, want {\"error\": ...}", name, out)
		}
	}
}

// It is hidden: not in kiyesi --help or the command reference.
func TestPullcheckIsHidden(t *testing.T) {
	_, out, _ := runCLI(t, "--help")
	if strings.Contains(out, "pullcheck") {
		t.Error("kiyesi --help lists pullcheck")
	}
}
