package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/update"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

type fakeReleases struct {
	latest string
	bin    []byte
	err    error
}

func (f fakeReleases) Latest(context.Context) (string, error) { return f.latest, nil }
func (f fakeReleases) Fetch(context.Context) (update.Release, []byte, error) {
	return update.Release{Version: f.latest}, f.bin, f.err
}

func useReleases(t *testing.T, f fakeReleases) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "kiyesi")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	oldR, oldE, oldUnit, oldRefresh := releases, executable, unitPath, refreshWith
	releases = func() releaseSource { return f }
	executable = func() (string, error) { return exe, nil }
	unitPath = filepath.Join(t.TempDir(), "none.service")
	refreshWith = func(string) error { return nil }
	t.Cleanup(func() { releases, executable, unitPath, refreshWith = oldR, oldE, oldUnit, oldRefresh })
	return exe
}

func TestUpdateSaysWhenThisIsTheNewest(t *testing.T) {
	useReleases(t, fakeReleases{latest: version.Version})
	if code, out, _ := runCLI(t, "update"); code != ExitOK || !strings.Contains(out, "is the newest") {
		t.Errorf("%d %s", code, out)
	}
}

func TestUpdateCheckOnlyTells(t *testing.T) {
	exe := useReleases(t, fakeReleases{latest: "99.0.0", bin: []byte("new")})
	if code, out, _ := runCLI(t, "update", "--check"); code != ExitOK || !strings.Contains(out, "kiyesi 99.0.0 is out") {
		t.Errorf("%d %s", code, out)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old" {
		t.Error("--check changed the program")
	}
}

func TestUpdateReplacesTheProgram(t *testing.T) {
	exe := useReleases(t, fakeReleases{latest: "99.0.0", bin: []byte("new")})
	if code, out, errOut := runCLI(t, "update"); code != ExitOK || !strings.Contains(out, "to 99.0.0, signature checked") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	if got, _ := os.ReadFile(exe); string(got) != "new" {
		t.Errorf("program is %q", got)
	}
}

func TestUpdateChangesNothingWhenACheckFails(t *testing.T) {
	exe := useReleases(t, fakeReleases{latest: "99.0.0", err: errors.New("the release's signature does not match. Nothing was changed")})
	if code, _, errOut := runCLI(t, "update"); code != ExitNoAccess || !strings.Contains(errOut, "signature does not match") {
		t.Errorf("%d %s", code, errOut)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old" {
		t.Error("the program changed")
	}
}

func TestUpdateLeavesAHomebrewInstallToHomebrew(t *testing.T) {
	useReleases(t, fakeReleases{latest: "99.0.0", bin: []byte("new")})
	cellar := filepath.Join(t.TempDir(), "Cellar", "kiyesi", "0.26.0", "bin", "kiyesi")
	_ = os.MkdirAll(filepath.Dir(cellar), 0o755)
	_ = os.WriteFile(cellar, []byte("old"), 0o755)
	executable = func() (string, error) { return cellar, nil }
	code, out, errOut := runCLI(t, "update")
	if code != ExitOK || !strings.Contains(out, "brew upgrade kiyesi") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if b, _ := os.ReadFile(cellar); string(b) != "old" {
		t.Errorf("Homebrew's copy was replaced")
	}
}

// A running agent restarts on the new version; one stopped with
// systemctl disable --now stays stopped.
func TestUpdateRestartsOnlyARunningAgent(t *testing.T) {
	for _, running := range []bool{true, false} {
		useReleases(t, fakeReleases{latest: "99.0.0", bin: []byte("new")})
		unitPath = filepath.Join(t.TempDir(), "kiyesi.service")
		_ = os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644)
		var calls []string
		oldRun, oldHas := runSystemctl, hasSystemctl
		t.Cleanup(func() { runSystemctl, hasSystemctl = oldRun, oldHas })
		hasSystemctl = func() bool { return true }
		runSystemctl = func(args ...string) error {
			calls = append(calls, strings.Join(args, " "))
			if args[0] == "is-active" && !running {
				return errors.New("exit status 3")
			}
			return nil
		}
		code, out, errOut := runCLI(t, "update")
		if code != ExitOK {
			t.Fatalf("exit %d: %s %s", code, out, errOut)
		}
		for _, c := range calls {
			if c == "restart kiyesi" || c == "start kiyesi" || (!running && c == "try-restart kiyesi") {
				t.Errorf("running=%v: ran systemctl %s", running, c)
			}
		}
		if running && !strings.Contains(out, "The agent restarted on the new version.") {
			t.Errorf("running agent: %s", out)
		}
		if !running && (strings.Contains(out, "restarted") || !strings.Contains(out, "The agent is stopped, so it stays stopped.")) {
			t.Errorf("stopped agent: %s", out)
		}
	}
}

// fakeSystemd stands in for systemctl, with a service file at unitPath
// holding have, and records each call.
func fakeSystemd(t *testing.T, have string, running bool) *[]string {
	t.Helper()
	unitPath = filepath.Join(t.TempDir(), "kiyesi.service")
	_ = os.WriteFile(unitPath, []byte(have), 0o644)
	var calls []string
	oldRun, oldHas := runSystemctl, hasSystemctl
	t.Cleanup(func() { runSystemctl, hasSystemctl = oldRun, oldHas })
	hasSystemctl = func() bool { return true }
	runSystemctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "is-active" && !running {
			return errors.New("exit status 3")
		}
		return nil
	}
	return &calls
}

// A server updated from a version with other service settings (such as
// the old 64 MB memory limit) gets this version's on the next update,
// even when it is already the newest, and the agent restarts with them.
func TestUpdateOnTheNewestBringsAnOldServiceFileUpToDate(t *testing.T) {
	exe := useReleases(t, fakeReleases{latest: version.Version})
	calls := fakeSystemd(t, strings.Replace(unitFile(exe), "MemoryMax=256M", "MemoryMax=64M", 1), true)
	code, out, errOut := runCLI(t, "update")
	if code != ExitOK || !strings.Contains(out, "is the newest") || !strings.Contains(out, "service settings are now up to date") || !strings.Contains(out, "restarted with them") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if got, _ := os.ReadFile(unitPath); string(got) != unitFile(exe) {
		t.Errorf("the service file was not rewritten:\n%s", got)
	}
	if want := []string{"daemon-reload", "is-active --quiet kiyesi", "try-restart kiyesi"}; strings.Join(*calls, ",") != strings.Join(want, ",") {
		t.Errorf("systemctl calls %v, want %v", *calls, want)
	}
}

// A service file that already matches is left alone, and the agent is not
// restarted for nothing.
func TestUpdateOnTheNewestLeavesACurrentServiceFile(t *testing.T) {
	exe := useReleases(t, fakeReleases{latest: version.Version})
	calls := fakeSystemd(t, unitFile(exe), true)
	code, out, _ := runCLI(t, "update")
	if code != ExitOK || strings.Contains(out, "settings") || strings.Contains(out, "restarted") {
		t.Fatalf("%d %q", code, out)
	}
	if len(*calls) != 0 {
		t.Errorf("systemctl calls %v, want none", *calls)
	}
}

// --check only tells, and never touches the service file.
func TestUpdateCheckLeavesTheServiceFile(t *testing.T) {
	useReleases(t, fakeReleases{latest: version.Version})
	calls := fakeSystemd(t, "old", true)
	if code, _, _ := runCLI(t, "update", "--check"); code != ExitOK {
		t.Fatal(code)
	}
	if got, _ := os.ReadFile(unitPath); string(got) != "old" || len(*calls) != 0 {
		t.Errorf("--check changed the service: %q %v", got, *calls)
	}
}

// After replacing the program, the new version is asked to write its own
// service settings before the agent restarts on it.
func TestUpdateAsksTheNewVersionForItsServiceSettingsBeforeRestarting(t *testing.T) {
	exe := useReleases(t, fakeReleases{latest: "99.0.0", bin: []byte("new")})
	calls := fakeSystemd(t, "old", true)
	refreshWith = func(got string) error {
		if got != exe {
			t.Errorf("asked %s, want %s", got, exe)
		}
		*calls = append(*calls, "refresh")
		return nil
	}
	if code, out, errOut := runCLI(t, "update"); code != ExitOK {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if want := []string{"refresh", "is-active --quiet kiyesi", "try-restart kiyesi"}; strings.Join(*calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls %v, want %v", *calls, want)
	}
}

// When the new version cannot write its settings, the update still holds
// and says how to finish.
func TestUpdateSaysHowToFinishWhenTheServiceSettingsFail(t *testing.T) {
	useReleases(t, fakeReleases{latest: "99.0.0", bin: []byte("new")})
	fakeSystemd(t, "old", true)
	refreshWith = func(string) error { return errors.New("exit status 1") }
	code, out, _ := runCLI(t, "update")
	if code != ExitOK || !strings.Contains(out, "run sudo kiyesi update once more") || !strings.Contains(out, "restarted on the new version") {
		t.Fatalf("%d %q", code, out)
	}
}

// The hidden --refresh-service, run by the update before, writes this
// version's service file and reloads systemd, without asking the network.
func TestRefreshServiceWritesThisVersionsSettings(t *testing.T) {
	exe := useReleases(t, fakeReleases{err: errors.New("no network in this test")})
	releases = func() releaseSource { t.Error("asked for releases"); return fakeReleases{} }
	calls := fakeSystemd(t, "old", true)
	if code, out, errOut := runCLI(t, "update", "--refresh-service"); code != ExitOK || out != "" {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if got, _ := os.ReadFile(unitPath); string(got) != unitFile(exe) {
		t.Errorf("service file not written: %q", got)
	}
	if strings.Join(*calls, ",") != "daemon-reload" {
		t.Errorf("calls %v", *calls)
	}
}
