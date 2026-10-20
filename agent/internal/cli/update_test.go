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
	oldR, oldE, oldUnit := releases, executable, unitPath
	releases = func() releaseSource { return f }
	executable = func() (string, error) { return exe, nil }
	unitPath = filepath.Join(t.TempDir(), "none.service")
	t.Cleanup(func() { releases, executable, unitPath = oldR, oldE, oldUnit })
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
