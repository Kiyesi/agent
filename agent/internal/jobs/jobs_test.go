package jobs

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"testing/fstest"
	"time"
)

func TestTakeIgnoresLinksAndBadNames(t *testing.T) {
	spool := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(secret, []byte(`{"name":"x","run_id":"1"}`), 0o600)
	_ = os.Symlink(secret, filepath.Join(spool, "a.start.json"))
	_ = os.WriteFile(filepath.Join(spool, "b.start.json"), []byte(`{"name":"../etc","run_id":"2"}`), 0o644)
	_ = os.WriteFile(filepath.Join(spool, "c.start.json"), []byte(`{"name":"ok-job","run_id":"3"}`), 0o644)
	runs := Take(spool)
	if len(runs) != 1 || runs[0].Name != "ok-job" {
		t.Errorf("runs = %+v", runs)
	}
}

// The spool takes files from every user, so a run's user is whoever owns
// its file: a user cannot record a run as root.
func TestTakeNamesTheFilesOwnerNotWhatTheFileClaims(t *testing.T) {
	spool := t.TempDir()
	_ = os.WriteFile(filepath.Join(spool, "a.start.json"), []byte(`{"name":"backup","run_id":"1","user":"root"}`), 0o600)
	runs := Take(spool)
	if len(runs) != 1 {
		t.Fatalf("runs = %+v", runs)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if runs[0].User != me.Username {
		t.Errorf("user = %q, want the file's owner %q", runs[0].User, me.Username)
	}
}

// A pipe in the spool is never waited on, and one user's flood of runs
// leaves room for others: the rest wait for the next go.
func TestTakeNeverWaitsOnAPipeAndCapsEachUser(t *testing.T) {
	spool := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(spool, "0.start.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		_ = os.WriteFile(filepath.Join(spool, fmt.Sprintf("r%02d.start.json", i)), []byte(fmt.Sprintf(`{"name":"job","run_id":"%d"}`, i)), 0o600)
	}
	done := make(chan []Run, 1)
	go func() { done <- Take(spool) }()
	select {
	case runs := <-done:
		if len(runs) != perUserRuns {
			t.Fatalf("one user got %d runs in one go", len(runs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Take waited on a pipe")
	}
	if left, _ := os.ReadDir(spool); len(left) != 40-perUserRuns {
		t.Errorf("%d files wait for the next go", len(left))
	}
}

func TestCronNext(t *testing.T) {
	at := time.Date(2026, 10, 11, 4, 10, 0, 0, time.UTC) // a Sunday
	for spec, want := range map[string]string{
		"0 4 * * *":      "2026-10-12T04:00:00Z",
		"*/5 * * * *":    "2026-10-11T04:15:00Z",
		"@hourly":        "2026-10-11T05:00:00Z",
		"0 7 * * mon":    "2026-10-12T07:00:00Z",
		"30 3 1 * *":     "2026-11-01T03:30:00Z",
		"0 9 1 * 6":      "2026-10-17T09:00:00Z", // the 1st or a Saturday, as cron does
		"0 0 29 feb *":   "2028-02-29T00:00:00Z",
		"15 4-6/2 * * *": "2026-10-11T04:15:00Z",
	} {
		c, err := ParseCron(spec)
		if err != nil {
			t.Errorf("%s: %v", spec, err)
			continue
		}
		next := c.Next(at)
		if spec == "0 0 29 feb *" {
			// More than a year away: not found, as cron's own rule allows.
			if !next.IsZero() && next.Format(time.RFC3339) != want {
				t.Errorf("%s: next = %s", spec, next)
			}
			continue
		}
		if got := next.Format(time.RFC3339); got != want {
			t.Errorf("%s: next = %s, want %s", spec, got, want)
		}
	}
	for _, bad := range []string{"* * *", "61 * * * *", "0 4 * * funday", "@reboot"} {
		if _, err := ParseCron(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

type fakeRunner struct{}

func (fakeRunner) Has(string) bool { return true }
func (fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && args[1] == "kiyesi-backup.timer" {
		return []byte("Sun 2026-10-11 03:30:00 UTC\n"), nil
	}
	// The service's last run: it failed, as a backup whose wrapper broke did.
	if name == "systemctl" && args[1] == "kiyesi-backup.service" {
		return []byte("Result=exit-code\nExecMainStatus=2\nExecMainStartTimestamp=Sun 2026-10-11 03:31:40 UTC\n"), nil
	}
	return nil, os.ErrNotExist
}

func TestFindReadsCrontabsAndTimers(t *testing.T) {
	at := time.Date(2026, 10, 11, 4, 10, 0, 0, time.UTC)
	fsys := fstest.MapFS{
		"etc/crontab":                              {Data: []byte("SHELL=/bin/sh\n# m h dom mon dow user command\n0 4 * * * root S=$(date +%s); /opt/backup.sh; kiyesi job done --name nightly-backup --exit $? --started $S\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")},
		"etc/cron.d/reports":                       {Data: []byte("0 7 * * 1 app node report.js; /usr/local/bin/kiyesi job done --name=weekly-sales-report --exit $?\n")},
		"var/spool/cron/crontabs/app":              {Data: []byte("*/5 * * * * node send.js; kiyesi job done --name send-order-emails --exit $?\n")},
		"etc/systemd/system/kiyesi-backup.service": {Data: []byte("[Service]\nExecStart=/usr/local/sbin/kiyesi-backup\nExecStopPost=/usr/local/bin/kiyesi job done --name kiyesi-backup --exit $EXIT_STATUS\n")},
		"etc/systemd/system/kiyesi-backup.timer":   {Data: []byte("[Timer]\nOnCalendar=*-*-* 03:30:00 UTC\n")},
	}
	got := Find(context.Background(), fsys, fakeRunner{}, at)
	want := map[string]string{
		"nightly-backup":      "cron 0 4 * * * 2026-10-12T04:00:00Z",
		"weekly-sales-report": "cron 0 7 * * 1 2026-10-12T07:00:00Z",
		"send-order-emails":   "cron */5 * * * * 2026-10-11T04:15:00Z",
		"kiyesi-backup":       "systemd *-*-* 03:30:00 UTC 2026-10-11T03:30:00Z",
	}
	if len(got) != len(want) {
		t.Fatalf("found %d: %+v", len(got), got)
	}
	for _, s := range got {
		if line := s.Source + " " + s.Schedule + " " + s.NextAt; line != want[s.Name] {
			t.Errorf("%s: %q, want %q", s.Name, line, want[s.Name])
		}
	}
}

// A timer's service says how its last run went, so a job that fails before
// it can record a start is known as failed.
func TestTimersSayHowTheLastRunWent(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/systemd/system/kiyesi-backup.service": {Data: []byte("[Service]\nExecStartPre=/usr/local/bin/kiyesi job start --name kiyesi-backup\nExecStart=/usr/local/sbin/kiyesi-backup\nExecStopPost=/usr/local/bin/kiyesi job done --name kiyesi-backup --exit $EXIT_STATUS\n")},
		"etc/systemd/system/kiyesi-backup.timer":   {Data: []byte("[Timer]\nOnCalendar=*-*-* 03:30:00 UTC\nRandomizedDelaySec=15min\n")},
	}
	got := Find(context.Background(), fsys, fakeRunner{}, time.Date(2026, 10, 11, 4, 10, 0, 0, time.UTC))
	if len(got) != 1 {
		t.Fatalf("found %+v", got)
	}
	s := got[0]
	if s.Unit != "kiyesi-backup.service" || s.LastRunAt != "2026-10-11T03:31:40Z" || s.LastResult != "exit-code" || s.LastExit == nil || *s.LastExit != 2 {
		t.Errorf("last run: %+v", s)
	}
	var none Schedule
	lastRun(&none, "Result=success\nExecMainStatus=0\nExecMainStartTimestamp=\n")
	if none.LastRunAt != "" || none.LastExit != nil {
		t.Errorf("a service that never ran: %+v", none)
	}
}

func TestParseElapse(t *testing.T) {
	for in, want := range map[string]string{
		"Mon 2026-10-12 03:37:21 UTC\n": "2026-10-12T03:37:21Z",
		"@1791689400":                   "2026-10-11T03:30:00Z",
	} {
		got, ok := parseElapse(in)
		if !ok || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("%q: %v %v", in, got, ok)
		}
	}
	if _, ok := parseElapse("n/a"); ok {
		t.Error("n/a should not parse")
	}
}

// Record notes a run the job made on its own: its name, exit code and, with
// a start, its length. Kiyesi starts nothing.
func TestRecordNotesARunWithoutStartingAnything(t *testing.T) {
	spool := t.TempDir()
	start := time.Date(2026, 10, 11, 4, 0, 0, 0, time.UTC)
	end := start.Add(192 * time.Second)
	if err := Record(spool, "nightly-backup", 3, start, end, func() string { return "run-1" }); err != nil {
		t.Fatal(err)
	}
	runs := Take(spool)
	if len(runs) != 1 {
		t.Fatalf("records = %d", len(runs))
	}
	r := runs[0]
	if r.Name != "nightly-backup" || *r.ExitCode != 3 || *r.DurationMs != 192000 || r.StartedAt != "2026-10-11T04:00:00Z" || r.EndedAt != "2026-10-11T04:03:12Z" {
		t.Errorf("run = %+v", r)
	}
	// Without a start, or one after the end, the run is noted at its end.
	if err := Record(spool, "x", 0, time.Time{}, end, func() string { return "run-2" }); err != nil {
		t.Fatal(err)
	}
	if r := Take(spool)[0]; r.StartedAt != r.EndedAt || *r.DurationMs != 0 {
		t.Errorf("no start: %+v", r)
	}
	if err := Record(filepath.Join(t.TempDir(), "missing"), "x", 0, start, end, func() string { return "r" }); err == nil {
		t.Error("a spool that is not there should say so")
	}
}
