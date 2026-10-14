package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func TestLevelOf(t *testing.T) {
	for line, want := range map[string]string{
		`{"level":50,"time":1,"msg":"query failed"}`: "error",
		`{"level":40,"msg":"slow"}`:                  "warn",
		`{"level":30,"msg":"request completed"}`:     "info",
		`{"level":"error","msg":"x"}`:                "error",
		`{"severity":"WARNING","message":"x"}`:       "warn",
		`{"msg":"handled request","status":502}`:     "error",
		// Caddy says info on every request; the status decides.
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"uri":"/"},"status":502}`: "error",
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"uri":"/"},"status":404}`: "info",
		`2026/10/10 10:41:06 [error] 31#31: *9 connect() failed (111: Connection refused)`:                       "error",
		`2026/10/10 10:41:06 [warn] 31#31: an upstream response is buffered`:                                     "warn",
		`2026/10/10 10:41:06 [notice] 1#1: start worker processes`:                                               "info",
		`FATAL ERROR: Reached heap limit Allocation failed`:                                                      "error",
		`time="2026-10-10T10:00:00Z" level=error msg="dial tcp: refused"`:                                        "error",
		`level=warn msg="disk 81% full"`:                                                                         "warn",
		`Traceback (most recent call last):`:                                                                     "error",
		`panic: runtime error: index out of range`:                                                               "error",
		`Error: connect ECONNREFUSED 127.0.0.1:5432`:                                                             "error",
		`[2026-10-10 10:00:00] WARNING: Heap usage at 91%`:                                                       "warn",
		`(node:1) DeprecationWarning: Buffer() is deprecated`:                                                    "warn",
		`203.0.113.9 - - [10/Oct/2026:10:00:30 +0000] "GET / HTTP/1.1" 502 5 "-" "ua"`:                           "error",
		`203.0.113.9 - - [10/Oct/2026:10:00:30 +0000] "GET / HTTP/1.1" 404 5 "-" "ua"`:                           "info",
		// Ordinary words are not levels.
		`Processed 12 orders with 0 errors`: "info",
		`Server listening on port 3000`:     "info",
		`terror alert: nothing to see here`: "info",
	} {
		if got := LevelOf(line); got != want {
			t.Errorf("LevelOf(%q) = %s, want %s", line, got, want)
		}
	}
}

func TestTheMinuteHasLimitsAndKeepsErrorsFirst(t *testing.T) {
	at := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	b := logBuffer{}
	for i := 0; i < MaxLogLines+50; i++ {
		b.add(LogLine{At: at, Source: "app", Kind: "container", Text: fmt.Sprintf("line %d", i)})
	}
	b.add(LogLine{At: at, Source: "app", Kind: "container", Text: "ERROR: the one that matters"})
	b.add(LogLine{At: at, Source: "app", Kind: "container", Text: strings.Repeat("é", MaxLineBytes)})
	logs := b.take(at)
	if logs.Dropped != 51 {
		t.Errorf("dropped = %d, want 51", logs.Dropped)
	}
	var sawError bool
	for _, l := range logs.Lines {
		if l.Text == "ERROR: the one that matters" && l.Level == "error" {
			sawError = true
		}
	}
	if !sawError {
		t.Error("an error over the line limit should use the reserve")
	}
	last := logs.Lines[len(logs.Lines)-1]
	if last.Source != "kiyesi" || !strings.Contains(last.Text, "left out 51 lines") {
		t.Errorf("last line = %+v", last)
	}
	if b.take(at) != nil {
		t.Error("take should empty the buffer")
	}

	// One megabyte at most, and each line cut at 8 KB without breaking a character.
	b = logBuffer{}
	big := strings.Repeat("x", 20<<10)
	for i := 0; i < 200; i++ {
		b.add(LogLine{At: at, Source: "app", Text: big})
	}
	logs = b.take(at)
	size := 0
	for _, l := range logs.Lines[:len(logs.Lines)-1] {
		size += len(l.Text)
		if !strings.HasSuffix(l.Text, "…[cut by Kiyesi]") || len(l.Text) > MaxLineBytes+40 {
			t.Fatalf("line not cut: %d bytes", len(l.Text))
		}
	}
	if size > MaxLogBytes || logs.Dropped == 0 {
		t.Errorf("size = %d, dropped = %d", size, logs.Dropped)
	}
	if got := cut(strings.Repeat("é", 10), 5); got != "éé" {
		t.Errorf("cut = %q", got)
	}
}

func TestRulesExcludeSourcesAndDropLines(t *testing.T) {
	b := logBuffer{rules: LogRules{Exclude: []string{"worker-*", "cron"}, Drop: []string{"GET /health"}}}
	at := time.Now()
	for _, l := range []LogLine{
		{At: at, Source: "worker-1", Text: "skipped by name"},
		{At: at, Source: "cron", Text: "skipped by name"},
		{At: at, Source: "api", Text: `"GET /health HTTP/1.1" 200`},
		{At: at, Source: "api", Text: "kept"},
		{At: at, Source: "api", Text: "   "},
	} {
		b.add(l)
	}
	logs := b.take(at)
	if len(logs.Lines) != 1 || logs.Lines[0].Text != "kept" || logs.Dropped != 0 {
		t.Errorf("lines = %+v", logs)
	}
}

// fakeJournal answers journalctl like systemd does, with the entries
// matching the --priority or --unit filters given.
type fakeJournal struct {
	entries []map[string]string
	calls   [][]string
}

func (f *fakeJournal) Has(name string) bool { return name == "journalctl" }
func (f *fakeJournal) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	var units []string
	warnOnly := false
	for _, a := range args {
		if u, ok := strings.CutPrefix(a, "--unit="); ok {
			units = append(units, u)
		}
		if a == "--priority=warning" {
			warnOnly = true
		}
	}
	var out []byte
	for _, e := range f.entries {
		if warnOnly && e["PRIORITY"] > "4" {
			continue
		}
		if len(units) > 0 && !contains(units, e["_SYSTEMD_UNIT"]) {
			continue
		}
		line, _ := json.Marshal(e)
		out = append(append(out, line...), '\n')
	}
	return out, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestTheSystemLog(t *testing.T) {
	start := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	usec := func(s int) string { return fmt.Sprint(start.Add(time.Duration(s) * time.Second).UnixMicro()) }
	j := &fakeJournal{entries: []map[string]string{
		// Your own service: every line.
		{"MESSAGE": "orders worker started", "PRIORITY": "6", "_SYSTEMD_UNIT": "myapp.service", "__REALTIME_TIMESTAMP": usec(10)},
		{"MESSAGE": "ERROR could not reach the database", "PRIORITY": "3", "_SYSTEMD_UNIT": "myapp.service", "__REALTIME_TIMESTAMP": usec(11)},
		// Cron: every line.
		{"MESSAGE": "(root) CMD (/usr/local/bin/backup)", "PRIORITY": "6", "_SYSTEMD_UNIT": "cron.service", "SYSLOG_IDENTIFIER": "CRON", "__REALTIME_TIMESTAMP": usec(12)},
		// The system's own services: warnings and errors only.
		{"MESSAGE": "Started Daily apt download activities.", "PRIORITY": "6", "_SYSTEMD_UNIT": "apt-daily.service", "__REALTIME_TIMESTAMP": usec(13)},
		{"MESSAGE": "EXT4-fs error (device vda1): bad block", "PRIORITY": "3", "_TRANSPORT": "kernel", "__REALTIME_TIMESTAMP": usec(14)},
		{"MESSAGE": "docker.service: Failed with result 'exit-code'", "PRIORITY": "4", "_SYSTEMD_UNIT": "docker.service", "__REALTIME_TIMESTAMP": usec(15)},
		// Sign-ins and typed commands: never, by default.
		{"MESSAGE": "Failed password for root from 203.0.113.7 port 22", "PRIORITY": "4", "_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd", "SYSLOG_FACILITY": "10", "__REALTIME_TIMESTAMP": usec(16)},
		{"MESSAGE": "ada : COMMAND=/usr/bin/psql -W", "PRIORITY": "4", "SYSLOG_IDENTIFIER": "sudo", "SYSLOG_FACILITY": "10", "__REALTIME_TIMESTAMP": usec(17)},
		// Firewall blocks: mostly internet scans, so not by default.
		{"MESSAGE": "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.1 PROTO=TCP DPT=9050", "PRIORITY": "4", "_TRANSPORT": "kernel", "__REALTIME_TIMESTAMP": usec(19)},
		// A container's line: the Docker logs API sends those.
		{"MESSAGE": "from a container", "PRIORITY": "3", "CONTAINER_ID": "abc", "__REALTIME_TIMESTAMP": usec(18)},
		// Before the agent started: never.
		{"MESSAGE": "old error", "PRIORITY": "3", "_SYSTEMD_UNIT": "myapp.service", "__REALTIME_TIMESTAMP": fmt.Sprint(start.Add(-time.Hour).UnixMicro())},
	}}
	fsys := fstest.MapFS{
		"etc/systemd/system/myapp.service":                       {Data: []byte("[Service]\n")},
		"etc/systemd/system/multi-user.target.wants/ssh.service": {Data: []byte("x")},
	}
	sys := &system.System{FS: fsys, Exec: j}
	var jr journal
	b := logBuffer{}
	jr.read(context.Background(), sys, JournalRules{On: true}, start, &b)
	if len(j.calls) != 0 || len(b.lines) != 0 {
		t.Fatal("the first minute only notes the time")
	}
	jr.read(context.Background(), sys, JournalRules{On: true}, start.Add(time.Minute), &b)
	got := map[string]string{}
	for _, l := range b.lines {
		got[l.Text] = l.Source + " " + l.Level
	}
	want := map[string]string{
		"orders worker started":                          "myapp info",
		"ERROR could not reach the database":             "myapp error",
		"(root) CMD (/usr/local/bin/backup)":             "cron info",
		"EXT4-fs error (device vda1): bad block":         "kernel error",
		"docker.service: Failed with result 'exit-code'": "docker warn",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("lines =\n%v\nwant\n%v", got, want)
	}
	// The next minute reads only what is newer.
	b = logBuffer{}
	jr.read(context.Background(), sys, JournalRules{On: true}, start.Add(2*time.Minute), &b)
	if len(b.lines) != 0 {
		t.Errorf("read twice: %+v", b.lines)
	}

	// With auth on, sign-in records are sent too; with the journal off, nothing.
	var jr2 journal
	b = logBuffer{}
	jr2.read(context.Background(), sys, JournalRules{On: true, Auth: true}, start, &b)
	jr2.read(context.Background(), sys, JournalRules{On: true, Auth: true}, start.Add(time.Minute), &b)
	if !strings.Contains(fmt.Sprint(b.lines), "Failed password") {
		t.Error("auth: true should send SSH records")
	}
	if strings.Contains(fmt.Sprint(b.lines), "UFW BLOCK") {
		t.Error("firewall lines need firewall: true")
	}
	var jr3 journal
	b = logBuffer{}
	jr3.read(context.Background(), sys, JournalRules{On: true, Firewall: true}, start, &b)
	jr3.read(context.Background(), sys, JournalRules{On: true, Firewall: true}, start.Add(time.Minute), &b)
	if !strings.Contains(fmt.Sprint(b.lines), "UFW BLOCK") {
		t.Error("firewall: true should send firewall lines")
	}
	calls := len(j.calls)
	jr2.read(context.Background(), sys, JournalRules{On: false}, start.Add(3*time.Minute), &b)
	if len(j.calls) != calls {
		t.Error("journal off should not run journalctl")
	}
}

func TestContainerOutputFilesAndEventsBecomeLines(t *testing.T) {
	start := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	now := start
	docker := &fakeDocker{
		list: []system.Container{
			{ID: id, Name: "checkout-api", Image: "checkout-api:3.8.0", ImageID: "sha256:a", Status: "running", StartedAt: "2026-10-09T08:00:00Z"},
		},
		lines: map[string][]system.LogLine{id: {
			{At: start.Add(-time.Minute), Text: "before the agent: never sent"},
			{At: start.Add(20 * time.Second), Text: `{"level":50,"msg":"payment failed"}`},
		}},
	}
	fs := files("100", "900", "1000", "2000", "3", "1000000", "old\n")
	fs["var/log/nginx/error.log"] = &fstest.MapFile{Data: []byte("old error\n")}
	sys := &system.System{FS: fs, Docker: docker, Now: func() time.Time { return now }}
	c := &Collector{Sys: sys, Logs: true}
	c.Collect(context.Background())
	if c.TakeLogs() != nil {
		t.Fatal("the first minute only notes where each log ends")
	}

	now = start.Add(time.Minute)
	fs = files("100", "900", "1000", "2000", "4", "1000000", "old\n"+`203.0.113.9 - - [10/Oct/2026:10:00:30 +0000] "GET /api/orders HTTP/1.1" 502 5 "-" "ua"`+"\n")
	fs["var/log/nginx/error.log"] = &fstest.MapFile{Data: []byte("old error\n2026/10/10 10:00:31 [error] 31#31: connect() failed\n")}
	sys.FS = fs
	// A deploy: a new container starts after the agent, and its first lines are kept.
	docker.list = append(docker.list, system.Container{ID: "new", Name: "worker", Image: "worker:2", Status: "running", StartedAt: start.Add(40 * time.Second).Format(time.RFC3339Nano)})
	docker.lines["new"] = []system.LogLine{{At: start.Add(41 * time.Second), Text: "Error: missing QUEUE_URL"}}
	c.Collect(context.Background())
	logs := c.TakeLogs()
	got := []string{}
	for _, l := range logs.Lines {
		got = append(got, l.Source+"|"+l.Kind+"|"+l.Level+"|"+l.Text)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		`checkout-api|container|error|{"level":50,"msg":"payment failed"}`,
		`worker|container|error|Error: missing QUEUE_URL`,
		`nginx|file|error|203.0.113.9`,
		`nginx error|file|error|2026/10/10 10:00:31 [error]`,
		`kernel|event|error|Out of memory: 1 process killed`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "before the agent") || strings.Contains(joined, "old error") {
		t.Errorf("old lines sent:\n%s", joined)
	}
	// Oldest first.
	for i := 1; i < len(logs.Lines); i++ {
		if logs.Lines[i].At.Before(logs.Lines[i-1].At) {
			t.Fatalf("out of order:\n%s", joined)
		}
	}

	// Rotation: the file shrank, so it is read from the start.
	now = start.Add(2 * time.Minute)
	fs["var/log/nginx/error.log"] = &fstest.MapFile{Data: []byte("2026/10/10 10:01:10 [warn] 31#31: after rotation\n")}
	c.Collect(context.Background())
	logs = c.TakeLogs()
	if logs == nil || !strings.Contains(fmt.Sprint(logs.Lines), "after rotation") {
		t.Errorf("after rotation: %+v", logs)
	}

	// Logs off: nothing is gathered, and requests are still counted.
	c.Logs = false
	now = start.Add(3 * time.Minute)
	docker.lines[id] = append(docker.lines[id], system.LogLine{At: start.Add(170 * time.Second), Text: "ERROR not sent"})
	c.Collect(context.Background())
	if l := c.TakeLogs(); l != nil {
		t.Errorf("logs off sent %+v", l)
	}
}
