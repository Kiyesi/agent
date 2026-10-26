package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/guard"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

// guardServer is a server whose /etc is a temporary folder, with stand-ins
// for the scan, the services and the sites.
func guardServer(t *testing.T) (etc string) {
	t.Helper()
	etc = filepath.Join(t.TempDir(), "etc")
	if err := os.MkdirAll(filepath.Join(etc, "nginx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "nginx/nginx.conf"), []byte("ok;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := struct {
		root   string
		asRoot func() bool
		store  func() guard.Store
		scanF  func(context.Context, string) (scan.Report, error)
		probe  func() guard.Probe
		ports  func() []int
	}{guardRoot, guardAsRoot, guardStore, guardScan, guardProbe, guardPorts}
	t.Cleanup(func() {
		guardRoot, guardAsRoot, guardStore, guardScan, guardProbe, guardPorts = old.root, old.asRoot, old.store, old.scanF, old.probe, old.ports
	})
	t.Setenv("KIYESI_ETC", t.TempDir())
	guardRoot = etc
	guardAsRoot = func() bool { return true }
	dir := filepath.Join(t.TempDir(), "guard")
	guardStore = func() guard.Store { return guard.Store{Dir: dir} }
	guardScan = func(context.Context, string) (scan.Report, error) {
		r := scan.Report{}
		r.Grade.Letter, r.Grade.Score = "A", 95
		return r, nil
	}
	guardProbe = func() guard.Probe {
		return guard.Probe{
			Failed:     func(context.Context) []string { return nil },
			Containers: func(context.Context) []string { return []string{"api"} },
			Get:        func(context.Context, string) int { return 200 },
		}
	}
	guardPorts = func() []int { return []int{80} }
	return etc
}

// guard runs nothing and writes nothing: it says how the server is now and
// prints each step of the safe way to make the change, with the person's
// own command quoted as they gave it, for them to review and run.
func TestGuardPrintsTheSafeStepsAndRunsNothing(t *testing.T) {
	etc := guardServer(t)
	code, out, errOut := runCLI(t, "guard", "--check", "http://127.0.0.1:3000/health", "--", "sh", "-c", "echo hi > /etc/x")
	if code != ExitOK {
		t.Fatalf("code %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Kiyesi changes nothing on this server. It only suggests: you review each command and run it yourself.",
		"Now: grade A 95 · 0 failed services · 1 of 1 site answer · 1 container running",
		"1. If your provider offers snapshots, take one now.",
		"sudo tar -czf /root/etc-before-",
		"3. Make your change:\n       sh -c 'echo hi > /etc/x'",
		"systemctl --failed",
		"curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:3000/health",
		"sudo docker ps",
		"sudo tar -dzf /root/etc-before-",
		"sudo systemctl restart <the service that failed>",
		"delete the copy: it holds password hashes and keys",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("out lacks %q:\n%s", want, out)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(filepath.Dir(etc), "guard"))
	if _, err := os.Stat(filepath.Join(etc, "x")); err == nil || len(entries) != 0 {
		t.Fatal("guard ran the command or kept a copy")
	}
	code, out, _ = runCLI(t, "guard", "--no-restore", "--", "apt-get", "upgrade")
	if code != ExitOK || strings.Contains(out, "sudo tar -dzf") {
		t.Errorf("--no-restore: %d\n%s", code, out)
	}
}

func TestGuardChecksItsWords(t *testing.T) {
	guardServer(t)
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

// A run kiyesi guard recorded before 0.40.0 is listed, and guard undo prints
// the commands that put its settings back, changing nothing.
func TestGuardUndoOfAnOldRunPrintsTheCommands(t *testing.T) {
	etc := guardServer(t)
	store := guardStore()
	m := guard.Manifest{ID: "e207", Command: []string{"./deploy.sh"}, User: "ada", At: time.Now(), Root: etc,
		Files: []guard.File{{Path: "nginx/nginx.conf", Mode: 0o644, Sum: "not-the-same", Kept: true}}}
	data, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Join(store.Dir, "e207", "files", "nginx"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "e207", "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCLI(t, "guard", "list"); code != ExitOK || !strings.Contains(out, "e207") {
		t.Fatalf("list: %d\n%s", code, out)
	}
	code, out, _ := runCLI(t, "guard", "undo", "e207", "--yes")
	if code != ExitOK || !strings.Contains(out, "sudo cp -a "+filepath.Join(store.Dir, "e207", "files", "nginx", "nginx.conf")+" "+filepath.Join(etc, "nginx", "nginx.conf")) {
		t.Errorf("undo: %d\n%s", code, out)
	}
	if data, _ := os.ReadFile(filepath.Join(etc, "nginx/nginx.conf")); string(data) != "ok;\n" {
		t.Fatal("guard undo changed a file")
	}
}
