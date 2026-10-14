package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLIInput(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(args, IO{Out: &out, Err: &errOut, Environ: []string{"NO_COLOR=1"}, In: strings.NewReader(input)})
	return code, out.String(), errOut.String()
}

func TestServersDisconnectDeleteRestoreReconnect(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	if code, out, errOut := runCLI(t, "servers", "disconnect", "checkout-api-prod"); code != ExitOK || !strings.Contains(out, "Disconnected checkout-api-prod") {
		t.Errorf("disconnect: %d %q %q", code, out, errOut)
	}
	// The name typed wrong: nothing is deleted.
	code, _, errOut := runCLIInput(t, "checkout-api\n", "servers", "delete", "checkout-api-prod")
	if code != ExitUsage || !strings.Contains(errOut, "nothing was deleted") {
		t.Errorf("wrong name: %d %q", code, errOut)
	}
	// The name and the code, typed when asked.
	code, out, errOut := runCLIInput(t, "checkout-api-prod\n123 456\n", "servers", "delete", "checkout-api-prod")
	if code != ExitOK || !strings.Contains(out, "Deleted checkout-api-prod. It is erased for good on") || !strings.Contains(out, "kiyesi servers restore checkout-api-prod") {
		t.Errorf("delete: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(errOut, "Type the server's name to confirm") || !strings.Contains(errOut, "Code from your authenticator app") {
		t.Errorf("questions: %q", errOut)
	}
	if code, out, _ := runCLI(t, "servers", "restore", "OLD-WEB-1"); code != ExitOK || !strings.Contains(out, "Restored old-web-1") {
		t.Errorf("restore: %d %q", code, out)
	}
	if code, _, errOut := runCLI(t, "servers", "restore", "never-there"); code != ExitUsage || !strings.Contains(errOut, "No deleted server") {
		t.Errorf("restore unknown: %d %q", code, errOut)
	}
	want := []string{"disconnect", "delete checkout-api-prod 123456", "restore d1"}
	if strings.Join(serverCalls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", serverCalls, want)
	}
	if code, out, _ := runCLI(t, "servers", "reconnect", "checkout-api-prod", "--code", "123456"); code != ExitOK || !strings.Contains(out, "sudo kiyesi connect --token ksv_new") {
		t.Errorf("reconnect: %d %q", code, out)
	}
	if code, _, errOut := runCLI(t, "servers", "reconnect", "checkout-api-prod", "--code", "000000"); code == ExitOK || !strings.Contains(errOut, "That code is not right") {
		t.Errorf("reconnect wrong code: %d %q", code, errOut)
	}
}

func TestUninstallRemovesTheServiceAndItsFiles(t *testing.T) {
	dir := t.TempDir()
	etc, state := filepath.Join(dir, "etc"), filepath.Join(dir, "state")
	t.Setenv("KIYESI_ETC", etc)
	t.Setenv("KIYESI_STATE", state)
	for _, p := range []string{filepath.Join(etc, "token"), filepath.Join(etc, "agent.yaml"), filepath.Join(state, "outbox", "b.json.gz")} {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, []byte("api: https://api.example.com\n"), 0o600)
	}
	unit := filepath.Join(dir, "kiyesi.service")
	exe := filepath.Join(dir, "kiyesi")
	_ = os.WriteFile(unit, []byte("[Unit]\n"), 0o644)
	_ = os.WriteFile(exe, []byte("binary"), 0o755)
	var calls []string
	oldUnit, oldRun, oldHas, oldExe := unitPath, runSystemctl, hasSystemctl, executablePath
	t.Cleanup(func() { unitPath, runSystemctl, hasSystemctl, executablePath = oldUnit, oldRun, oldHas, oldExe })
	unitPath = unit
	runSystemctl = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }
	hasSystemctl = func() bool { return true }
	executablePath = func() (string, error) { return exe, nil }

	// Without yes, nothing happens.
	if code, _, errOut := runCLIInput(t, "no\n", "uninstall"); code != ExitUsage || !strings.Contains(errOut, "Nothing was removed") {
		t.Fatalf("declined: %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(etc, "token")); err != nil {
		t.Fatal("declining removed files")
	}
	code, out, errOut := runCLIInput(t, "yes\n", "uninstall")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, p := range []string{unit, etc, state, exe} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if strings.Join(calls, "|") != "disable --now kiyesi|daemon-reload" {
		t.Errorf("systemctl calls = %v", calls)
	}
	if !strings.Contains(out, "Kiyesi is removed from this server.") || !strings.Contains(out, "Disconnect to keep it until it expires, or Delete to erase it") {
		t.Errorf("out = %q", out)
	}
}
