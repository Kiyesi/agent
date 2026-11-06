package collect

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// streamJournal is a journalctl that can follow: each Stream starts a new
// pipe, and lines written to the newest one reach the agent as they come.
type streamJournal struct {
	mu     sync.Mutex
	starts [][]string
	w      *io.PipeWriter
	runs   int
}

func (j *streamJournal) Has(name string) bool { return name == "journalctl" }
func (j *streamJournal) Run(context.Context, string, ...string) ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.runs++
	return nil, nil
}
func (j *streamJournal) Stream(ctx context.Context, _ string, args ...string) (io.ReadCloser, func() error, error) {
	r, w := io.Pipe()
	j.mu.Lock()
	j.starts = append(j.starts, args)
	j.w = w
	j.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = w.Close()
	}()
	return r, func() error { return nil }, nil
}

func (j *streamJournal) write(t *testing.T, fields map[string]string) {
	t.Helper()
	b, _ := json.Marshal(fields)
	j.mu.Lock()
	w := j.w
	j.mu.Unlock()
	if _, err := w.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

func TestTheSystemLogComesFromOneFollowerWithTheSameRules(t *testing.T) {
	j := &streamJournal{}
	fsys := fstest.MapFS{"etc/systemd/system/shop.service": {Data: []byte("[Service]\n")}}
	c := &Collector{
		Sys:     &system.System{FS: fsys, Exec: j, Now: time.Now},
		Logs:    true,
		Journal: JournalRules{On: true},
		Signins: &SigninWatch{Path: filepath.Join(t.TempDir(), "signins.json")},
	}
	c.Collect(context.Background())
	if len(j.starts) != 1 {
		t.Fatalf("followers started: %d", len(j.starts))
	}
	args := strings.Join(j.starts[0], " ")
	for _, want := range []string{"--follow", "--lines=0", "PRIORITY=4", "+ _SYSTEMD_UNIT=shop.service", "SYSLOG_IDENTIFIER=sshd"} {
		if !strings.Contains(args, want) {
			t.Errorf("follower args lack %q: %s", want, args)
		}
	}
	now := strconv.FormatInt(time.Now().UnixMicro(), 10)
	j.write(t, map[string]string{"MESSAGE": "shop started", "PRIORITY": "6", "_SYSTEMD_UNIT": "shop.service", "__REALTIME_TIMESTAMP": now})
	j.write(t, map[string]string{"MESSAGE": "disk error", "PRIORITY": "3", "_SYSTEMD_UNIT": "kernel", "_TRANSPORT": "kernel", "__REALTIME_TIMESTAMP": now})
	j.write(t, map[string]string{"MESSAGE": "Accepted publickey for ada from 198.51.100.7 port 5 ssh2", "PRIORITY": "6", "SYSLOG_IDENTIFIER": "sshd", "__REALTIME_TIMESTAMP": now})
	j.write(t, map[string]string{"MESSAGE": "from a container", "PRIORITY": "3", "CONTAINER_ID": "abc", "__REALTIME_TIMESTAMP": now})
	time.Sleep(50 * time.Millisecond)
	_, events := c.Collect(context.Background())
	logs := c.TakeLogs()
	var texts []string
	for _, l := range logs.Lines {
		texts = append(texts, l.Text)
	}
	got := strings.Join(texts, "|")
	// Your service's line and the warning; never the sign-in (auth is off) nor a container's.
	if !strings.Contains(got, "shop started") || !strings.Contains(got, "disk error") || strings.Contains(got, "Accepted") || strings.Contains(got, "container") {
		t.Errorf("lines = %s", got)
	}
	// The sign-in watch read the same follower.
	if len(events) != 1 || events[0].Kind != "signin" || events[0].Subject != "ada" {
		t.Errorf("events = %+v", events)
	}
	// One follower, and no journalctl started each minute.
	if len(j.starts) != 1 || j.runs != 0 {
		t.Errorf("starts %d, runs %d", len(j.starts), j.runs)
	}
	// A new service of your own: the follower starts again with it.
	fsys["etc/systemd/system/api.service"] = &fstest.MapFile{Data: []byte("[Service]\n")}
	c.Collect(context.Background())
	if len(j.starts) != 2 || !strings.Contains(strings.Join(j.starts[1], " "), "_SYSTEMD_UNIT=api.service") {
		t.Errorf("not restarted for the new service: %v", j.starts)
	}
}

func TestTheFollowerKeepsAtMostItsBuffer(t *testing.T) {
	s := &journalStream{}
	for i := 0; i < streamBuffer+10; i++ {
		s.mu.Lock()
		if len(s.entries) >= streamBuffer {
			s.entries = s.entries[1:]
			s.dropped++
		}
		s.entries = append(s.entries, journalEntry{Realtime: strconv.Itoa(i)})
		s.mu.Unlock()
	}
	got := s.take()
	if len(got) != streamBuffer || got[0].Realtime != "10" {
		t.Errorf("kept %d, first %s", len(got), got[0].Realtime)
	}
	if len(s.take()) != 0 {
		t.Error("taken twice")
	}
}
