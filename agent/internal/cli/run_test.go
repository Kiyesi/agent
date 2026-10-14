package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPassesTheJobThroughAndRecordsIt(t *testing.T) {
	state := t.TempDir()
	t.Setenv("KIYESI_STATE", state)
	if err := os.MkdirAll(filepath.Join(state, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "run", "--name", "nightly-backup", "--", "sh", "-c", "echo backed up; exit 4")
	if code != 4 || out != "backed up\n" || errOut != "" {
		t.Errorf("code %d, out %q, err %q", code, out, errOut)
	}
	files, _ := os.ReadDir(filepath.Join(state, "runs"))
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	if len(names) != 2 || !strings.HasSuffix(strings.Join(names, " "), ".start.json") && !strings.Contains(strings.Join(names, " "), ".end.json") {
		t.Errorf("spool = %v", names)
	}
	if code, _, errOut := runCLI(t, "run", "--", "true"); code != ExitUsage || !strings.Contains(errOut, "--name") {
		t.Errorf("no name: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "run", "--name", "x"); code != ExitUsage || !strings.Contains(errOut, "after --") {
		t.Errorf("no command: %d %q", code, errOut)
	}
}
