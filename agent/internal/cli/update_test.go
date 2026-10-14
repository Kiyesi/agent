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
