package jobs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestExecuteKeepsTheJobAsItIsAndRecordsTheRun(t *testing.T) {
	spool := t.TempDir()
	var out, errOut bytes.Buffer
	n := 0
	ids := func() string { n++; return "run-1" }
	clock := []time.Time{time.Date(2026, 10, 11, 4, 0, 0, 0, time.UTC), time.Date(2026, 10, 11, 4, 3, 12, 0, time.UTC)}
	now := func() time.Time { t := clock[0]; clock = clock[1:]; return t }
	code := Execute(spool, "nightly-backup", []string{"sh", "-c", "echo dumped 3 GB; sleep 0.2; echo 'password=hunter2' >&2; exit 3"}, nil, &out, &errOut, ids, now)
	if code != 3 {
		t.Fatalf("exit code = %d, want the job's own 3", code)
	}
	if out.String() != "dumped 3 GB\n" || errOut.String() != "password=hunter2\n" {
		t.Errorf("output changed: %q %q", out.String(), errOut.String())
	}
	runs := Take(spool)
	if len(runs) != 2 {
		t.Fatalf("records = %d", len(runs))
	}
	// The start is sent before the end.
	if runs[0].EndedAt != "" || runs[1].EndedAt == "" {
		t.Fatalf("order: %+v", runs)
	}
	end := runs[1]
	if end.Name != "nightly-backup" || *end.ExitCode != 3 || *end.DurationMs != 192000 {
		t.Errorf("end = %+v", end)
	}
	if strings.Join(end.LastLines, "|") != "dumped 3 GB|password=hunter2" {
		t.Errorf("last lines = %q", end.LastLines)
	}
	if left, _ := os.ReadDir(spool); len(left) != 0 {
		t.Errorf("the spool keeps %d files after sending", len(left))
	}
}

func TestExecuteRunsTheJobEvenWithNowhereToRecord(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(filepath.Join(t.TempDir(), "missing"), "x", []string{"sh", "-c", "echo ok"}, nil, &out, &errOut, func() string { return "r" }, time.Now)
	if code != 0 || out.String() != "ok\n" {
		t.Errorf("code %d, output %q", code, out.String())
	}
	// One line says the run was not recorded, not one per record.
	if strings.Count(errOut.String(), "\n") != 1 || !strings.HasPrefix(errOut.String(), "kiyesi run: this run is not recorded") {
		t.Errorf("stderr = %q", errOut.String())
	}
	// No spool at all: the caller said why, so nothing more is said.
	errOut.Reset()
	if code := Execute("", "x", []string{"true"}, nil, &out, &errOut, func() string { return "r" }, time.Now); code != 0 || errOut.Len() != 0 {
		t.Errorf("no spool: code %d, stderr %q", code, errOut.String())
	}
	if code := Execute(t.TempDir(), "x", []string{"/no/such/command"}, nil, &out, &out, func() string { return "r" }, time.Now); code != 127 {
		t.Errorf("a missing command exits %d, want 127", code)
	}
}

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
	return nil, os.ErrNotExist
}

func TestFindReadsCrontabsAndTimers(t *testing.T) {
	at := time.Date(2026, 10, 11, 4, 10, 0, 0, time.UTC)
	fsys := fstest.MapFS{
		"etc/crontab":                              {Data: []byte("SHELL=/bin/sh\n# m h dom mon dow user command\n0 4 * * * root kiyesi run --name nightly-backup -- /opt/backup.sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")},
		"etc/cron.d/reports":                       {Data: []byte("0 7 * * 1 app /usr/local/bin/kiyesi run --name=weekly-sales-report -- node report.js\n")},
		"var/spool/cron/crontabs/app":              {Data: []byte("*/5 * * * * kiyesi run --name send-order-emails -- node send.js\n")},
		"etc/systemd/system/kiyesi-backup.service": {Data: []byte("[Service]\nExecStart=/usr/local/bin/kiyesi run --name kiyesi-backup -- /usr/local/sbin/kiyesi-backup\n")},
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
