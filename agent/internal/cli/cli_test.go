package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/kiyesi/kiyesi/agent/internal/version"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type noExec struct{}

func (noExec) Has(string) bool { return false }
func (noExec) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return nil, nil
}

// testSystem is a small server: 1 GB of memory and no swap, SSH with
// passwords on, ufw off, and a .env file every user can read.
func testSystem(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("backups:\n  paths: [/var/backups]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFlag = cfg
	old := newSystem
	t.Cleanup(func() { newSystem = old; configFlag = "" })
	newSystem = func(root bool, stateDir string) *system.System {
		return &system.System{
			FS: fstest.MapFS{
				"proc/loadavg":        {Data: []byte("0.10 0.20 0.30 1/100 1\n")},
				"proc/cpuinfo":        {Data: []byte("processor\t: 0\n")},
				"proc/meminfo":        {Data: []byte("MemTotal: 997212 kB\nMemAvailable: 500000 kB\nSwapTotal: 0 kB\n")},
				"proc/self/mounts":    {Data: []byte("/dev/root / ext4 rw 0 0\n")},
				"proc/net/tcp":        {Data: []byte("  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 0\n")},
				"etc/ssh/sshd_config": {Data: []byte("PasswordAuthentication yes\n")},
				"etc/ufw/ufw.conf":    {Data: []byte("ENABLED=no\n")},
				"srv/app/.env":        {Data: []byte("DB_PASSWORD=correct-horse-battery\n"), Mode: 0o644},
				"var/backups/db.sql":  {Data: []byte("x"), ModTime: time.Now().Add(-2 * time.Hour)},
				"var/log/kern.log":    {Data: []byte("")},
			},
			Exec: noExec{},
			Statfs: func(string) (system.Usage, error) {
				return system.Usage{TotalBytes: 100, FreeBytes: 60, AvailBytes: 55, TotalInodes: 10, FreeInodes: 9}, nil
			},
			State:    &system.MemState{M: map[string]string{}},
			Now:      time.Now,
			Root:     root,
			OS:       system.OSInfo{Name: "Ubuntu 24.04", Tested: true},
			Hostname: "test-server",
		}
	}
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if configFlag != "" && len(args) > 0 && args[0] == "scan" {
		args = append(args, "--config", configFlag)
	}
	code := Execute(args, IO{Out: &out, Err: &errOut, Environ: []string{"NO_COLOR=1"}})
	return code, out.String(), errOut.String()
}

var configFlag string

func TestScanPrintsTheReportAndSavesIt(t *testing.T) {
	testSystem(t)
	code, out, _ := runCLI(t, "scan")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{
		"Kiyesi " + version.Short() + " · read-only scan · nothing leaves this server",
		"test-server · Ubuntu 24.04 · ",
		"WARN  This server has 974 MB of memory and no swap",
		"WARN  SSH allows password login",
		// Without root and with ufw off, nftables and iptables rules cannot be
		// read, so the firewall is unknown: skipped, never passed.
		"SKIP  Firewall: needs root: run sudo kiyesi scan",
		"WARN  /srv/app/.env holds secrets and every user on this server can read it",
		"based on ",
		"Full report with every fix command: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "correct-horse-battery") {
		t.Fatal("a secret's value reached the terminal")
	}
	files, _ := filepath.Glob(filepath.Join(os.Getenv("XDG_STATE_HOME"), "kiyesi", "report-*.txt"))
	if len(files) != 1 {
		t.Fatalf("report files = %v", files)
	}
	data, _ := os.ReadFile(files[0])
	if strings.Contains(string(data), "correct-horse-battery") {
		t.Fatal("a secret's value reached the report file")
	}
	if !strings.Contains(string(data), "sudo chmod 600 /srv/app/.env") {
		t.Errorf("the report file should hold every fix:\n%s", data)
	}
}

func TestScanJSON(t *testing.T) {
	testSystem(t)
	code, out, _ := runCLI(t, "scan", "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var r struct {
		Schema string `json:"schema"`
		Grade  struct {
			Letter  string `json:"letter"`
			BasedOn int    `json:"based_on"`
			Total   int    `json:"total"`
		} `json:"grade"`
		ReportFile string `json:"report_file"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if r.Schema != "kiyesi.scan/v1" || r.Grade.Total != 23 || r.Grade.Letter == "" || r.ReportFile == "" {
		t.Errorf("report = %+v", r)
	}
	if strings.Contains(out, "correct-horse-battery") {
		t.Fatal("a secret's value reached the JSON")
	}
}

func TestFailOn(t *testing.T) {
	testSystem(t)
	if code, _, _ := runCLI(t, "scan", "--fail-on", "critical"); code != ExitOK {
		t.Errorf("no critical findings, exit = %d", code)
	}
	if code, _, _ := runCLI(t, "scan", "--fail-on", "warning"); code != ExitFindings {
		t.Errorf("warnings with --fail-on warning, exit = %d", code)
	}
	code, _, errOut := runCLI(t, "scan", "--fail-on", "major")
	if code != ExitUsage || !strings.Contains(errOut, "Example: kiyesi scan --fail-on critical") {
		t.Errorf("bad --fail-on: exit %d, %q", code, errOut)
	}
}

func TestMistakesExitWithTwoAndSayWhatToDo(t *testing.T) {
	code, _, errOut := runCLI(t, "scan", "--nope")
	if code != ExitUsage || !strings.Contains(errOut, "kiyesi --help") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	code, _, _ = runCLI(t, "frobnicate")
	if code != ExitUsage {
		t.Errorf("unknown command exit = %d", code)
	}
}

func TestBadSettingsExitWithTwo(t *testing.T) {
	testSystem(t)
	if err := os.WriteFile(configFlag, []byte("limits:\n  disk_warning_percent: 99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "scan")
	if code != ExitUsage || !strings.Contains(errOut, "Fix the file") {
		t.Errorf("exit %d, %q", code, errOut)
	}
}

func TestVersion(t *testing.T) {
	oldV, oldC := version.Version, version.Commit
	t.Cleanup(func() { version.Version, version.Commit = oldV, oldC })
	version.Version, version.Commit = "1.2.3", "abc1234"
	code, out, _ := runCLI(t, "version")
	if code != ExitOK || out != "kiyesi 1.2.3 (abc1234)\n" {
		t.Errorf("exit %d, %q", code, out)
	}
	_, out, _ = runCLI(t, "version", "--json")
	if !strings.Contains(out, `"version": "1.2.3"`) || !strings.Contains(out, `"commit": "abc1234"`) {
		t.Errorf("json: %q", out)
	}
	// Without a commit from the build, just the number.
	version.Commit = ""
	if _, out, _ := runCLI(t, "version"); out != "kiyesi 1.2.3\n" {
		t.Errorf("without a commit: %q", out)
	}
}

func TestHelpHasAWorkedExample(t *testing.T) {
	_, out, _ := runCLI(t, "scan", "--help")
	if !strings.Contains(out, "sudo kiyesi scan --fail-on critical") {
		t.Errorf("help has no example:\n%s", out)
	}
}
