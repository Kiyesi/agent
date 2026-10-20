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
	// Without a good name the job still runs, as cron expects, only unrecorded.
	for _, args := range [][]string{{"run", "--", "sh", "-c", "echo ran; exit 3"}, {"run", "--name", "bad name!", "--", "sh", "-c", "echo ran; exit 3"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 3 || out != "ran\n" || !strings.Contains(errOut, "this run is not recorded") || !strings.Contains(errOut, "--name") {
			t.Errorf("%v: %d %q %q", args, code, out, errOut)
		}
	}
	if files, _ := os.ReadDir(filepath.Join(state, "runs")); len(files) != 2 {
		t.Errorf("an unnamed run was recorded: %d files", len(files))
	}
	if code, _, errOut := runCLI(t, "run", "--name", "x"); code != ExitUsage || !strings.Contains(errOut, "after --") {
		t.Errorf("no command: %d %q", code, errOut)
	}
}
