package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/guard"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

// guardServer is a server whose /etc is a temporary folder, with stand-ins
// for the scan, the services and the sites. ran is what the command does.
func guardServer(t *testing.T, ran func(etc string) int) (etc string, restarted *[]string, failed *[]string) {
	t.Helper()
	etc = filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(filepath.Join(etc, "nginx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "nginx/nginx.conf"), []byte("ok;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var units, restarts []string
	site := 200
	old := struct {
		root   string
		asRoot func() bool
		store  func() guard.Store
		scanF  func(context.Context, string) (scan.Report, error)
		probe  func() guard.Probe
		pkgs   func(context.Context) []string
		ports  func() []int
		run    func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error)
		re     func(context.Context, string) error
	}{guardRoot, guardAsRoot, guardStore, guardScan, guardProbe, guardPackages, guardPorts, guardRun, guardRestart}
	t.Cleanup(func() {
		guardRoot, guardAsRoot, guardStore, guardScan, guardProbe = old.root, old.asRoot, old.store, old.scanF, old.probe
		guardPackages, guardPorts, guardRun, guardRestart = old.pkgs, old.ports, old.run, old.re
	})
	t.Setenv("KIYESI_ETC", t.TempDir())
	guardRoot = etc
	guardAsRoot = func() bool { return true }
	dir := filepath.Join(t.TempDir(), "guard")
	guardStore = func() guard.Store { return guard.Store{Dir: dir} }
	guardScan = func(context.Context, string) (scan.Report, error) {
		data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf"))
		r := scan.Report{}
		r.Grade.Letter, r.Grade.Score = "A", 95
		if string(data) != "ok;\n" {
			r.Grade.Letter, r.Grade.Score = "B", 80
		}
		return r, nil
	}
	guardProbe = func() guard.Probe {
		return guard.Probe{
			Failed:     func(context.Context) []string { return units },
			Containers: func(context.Context) []string { return []string{"api"} },
			Get:        func(context.Context, string) int { return site },
		}
	}
	pkgs := []string{"nginx 1.24.0-1"}
	guardPackages = func(context.Context) []string { return pkgs }
	guardPorts = func() []int { return []int{80} }
	guardRun = func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		code := ran(etc)
		data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf"))
		if string(data) != "ok;\n" {
			units, site = []string{"nginx.service"}, 502
		}
		pkgs = []string{"nginx 1.24.0-2"}
		return code, nil
	}
	guardRestart = func(_ context.Context, u string) error {
		restarts = append(restarts, u)
		units, site = nil, 200
		return nil
	}
	return etc, &restarts, &units
}

func breakNginx(etc string) int {
	_ = os.WriteFile(filepath.Join(etc, "nginx/nginx.conf"), []byte("broken\n"), 0o644)
	return 0
}

func TestGuardSaysAllIsWell(t *testing.T) {
	guardServer(t, func(string) int { return 0 })
	code, out, errOut := runCLI(t, "guard", "--", "apt-get", "upgrade")
	if code != ExitOK {
		t.Fatalf("code %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"Saved", "grade A 95 · 0 failed services · 1 of 1 site answer · 1 container running", "No service failed", "Packages changed: 1", "nginx=1.24.0-1", "sudo kiyesi guard undo"} {
		if !strings.Contains(out, want) {
			t.Errorf("out lacks %q:\n%s", want, out)
		}
	}
}

func TestGuardPutsTheSettingsBackWhenSomethingBroke(t *testing.T) {
	etc, restarted, _ := guardServer(t, breakNginx)
	code, out, _ := runCLI(t, "guard", "--restore", "--", "./deploy.sh")
	if code != ExitOK {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, want := range []string{"✗ nginx.service failed", "http://127.0.0.1/ answers 502 (before: 200)", "the grade fell from A 95 to B 80", "Put back 1 settings file", "Restarted nginx.service", "Working again"} {
		if !strings.Contains(out, want) {
			t.Errorf("out lacks %q:\n%s", want, out)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "ok;\n" {
		t.Fatalf("nginx.conf = %q", data)
	}
	if strings.Join(*restarted, ",") != "nginx.service" {
		t.Fatalf("restarted %v", *restarted)
	}
}

func TestGuardAsksAndLeavesItWhenToldNo(t *testing.T) {
	etc, restarted, _ := guardServer(t, breakNginx)
	code, out, _ := runCLI(t, "guard", "--", "./deploy.sh")
	if code != ExitFindings || !strings.Contains(out, "sudo kiyesi guard undo") || len(*restarted) != 0 {
		t.Fatalf("code %d, restarted %v:\n%s", code, *restarted, out)
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "broken\n" {
		t.Fatal("put back without a yes")
	}
	// Later, by its id.
	list, _ := guardStore().List()
	if len(list) != 1 {
		t.Fatalf("runs = %d", len(list))
	}
	code, out, _ = runCLI(t, "guard", "undo", list[0].ID, "--yes")
	if code != ExitOK || !strings.Contains(out, "Put back 1 settings file") {
		t.Fatalf("undo: code %d\n%s", code, out)
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "ok;\n" {
		t.Fatal("not put back by undo")
	}
	code, out, _ = runCLI(t, "guard", "list")
	if code != ExitOK || !strings.Contains(out, list[0].ID) || !strings.Contains(out, "settings put back") {
		t.Fatalf("list: %d\n%s", code, out)
	}
}

func TestGuardPassesOnTheCommandsExitCode(t *testing.T) {
	guardServer(t, func(string) int { return 3 })
	if code, _, _ := runCLI(t, "guard", "--", "false"); code != 3 {
		t.Fatalf("code %d, want the command's own 3", code)
	}
}

func TestGuardChecksItsWords(t *testing.T) {
	guardServer(t, func(string) int { return 0 })
	if code, _, errOut := runCLI(t, "guard", "apt-get"); code != ExitUsage || !strings.Contains(errOut, "after --") {
		t.Fatalf("no --: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "guard", "--check", "http://example.com/", "--", "true"); code != ExitUsage || !strings.Contains(errOut, "not this server") {
		t.Fatalf("outside address: %d %q", code, errOut)
	}
	guardAsRoot = func() bool { return false }
	if code, _, errOut := runCLI(t, "guard", "--", "true"); code != ExitNoAccess || !strings.Contains(errOut, "sudo kiyesi guard") {
		t.Fatalf("not root: %d %q", code, errOut)
	}
}

func TestFixOffMeansKiyesiNeverPutsSettingsBack(t *testing.T) {
	etc, restarted, _ := guardServer(t, breakNginx)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("fix: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "guard", "--restore", "--config", cfg, "--", "./deploy.sh")
	if code != ExitFindings || !strings.Contains(out, "fix: off") || len(*restarted) != 0 {
		t.Fatalf("code %d, restarted %v:\n%s", code, *restarted, out)
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "broken\n" {
		t.Fatal("put back with fix: off")
	}
	list, _ := guardStore().List()
	if code, _, errOut := runCLI(t, "guard", "undo", list[0].ID, "--yes", "--config", cfg); code != ExitNoAccess || !strings.Contains(errOut, "fix: off") {
		t.Fatalf("undo with fix: off: %d %q", code, errOut)
	}
}
