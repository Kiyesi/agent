package cli

import (
	"strings"
	"testing"
)

// Every server command named exists, and on Windows each says it runs on a
// Linux server instead of failing on what Windows lacks; the commands that
// ask the service are left alone.
func TestServerCommandsSayTheyRunOnALinuxServerOnWindows(t *testing.T) {
	root := newRoot(IO{})
	for path := range serverOnly {
		args := strings.Fields(path)[1:]
		cmd, _, err := root.Find(args)
		if err != nil || cmd.CommandPath() != path {
			t.Errorf("%q is not a command (%v)", path, err)
		}
	}
	old := hostOS
	t.Cleanup(func() { hostOS = old })
	hostOS = "windows"
	for _, args := range [][]string{{"scan"}, {"fix", "--dry-run"}, {"keys"}, {"guard", "list"}, {"connect", "--token", "-"}} {
		code, _, errOut := runCLI(t, args...)
		if code != ExitUsage || !strings.Contains(errOut, "kiyesi "+strings.Join(args[:1], " ")) || !strings.Contains(errOut, "runs on a Linux server") {
			t.Errorf("%v on Windows: %d %q", args, code, errOut)
		}
	}
	if code, out, _ := runCLI(t, "version"); code != ExitOK || !strings.Contains(out, "kiyesi") {
		t.Errorf("version on Windows: %d %q", code, out)
	}
}
