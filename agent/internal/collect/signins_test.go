package collect

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// sshJournal answers journalctl with sshd's lines after --since.
type sshJournal struct {
	lines []struct {
		at  time.Time
		msg string
	}
	args []string
}

func (j *sshJournal) Has(name string) bool { return name == "journalctl" }
func (j *sshJournal) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	j.args = args
	var since int64
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--since=@"); ok {
			since, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	var out []byte
	for _, l := range j.lines {
		if l.at.Unix() < since {
			continue
		}
		b, _ := json.Marshal(map[string]string{"MESSAGE": l.msg, "__REALTIME_TIMESTAMP": strconv.FormatInt(l.at.UnixMicro(), 10)})
		out = append(append(out, b...), '\n')
	}
	return out, nil
}

func (j *sshJournal) add(at time.Time, msg string) {
	j.lines = append(j.lines, struct {
		at  time.Time
		msg string
	}{at, msg})
}

func TestSigninWatchSendsOnlyNewPairs(t *testing.T) {
	start := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	j := &sshJournal{}
	j.add(start.Add(-time.Hour), "Accepted publickey for ada from 198.51.100.7 port 51234 ssh2: ED25519 SHA256:x")
	sys := &system.System{Exec: j}
	path := filepath.Join(t.TempDir(), "signins.json")
	w := &SigninWatch{Path: path}
	// The first minute only notes the time: nothing old is sent.
	if ev := w.Read(context.Background(), sys, start); len(ev) != 0 {
		t.Fatalf("first minute sent %+v", ev)
	}
	j.add(start.Add(30*time.Second), "Accepted publickey for ada from 198.51.100.7 port 51234 ssh2: ED25519 SHA256:x")
	j.add(start.Add(31*time.Second), "Failed password for root from 203.0.113.9 port 4444 ssh2")
	j.add(start.Add(40*time.Second), "Accepted password for root from ::ffff:203.0.113.9 port 4445 ssh2")
	j.add(start.Add(50*time.Second), "Accepted publickey for ada from 198.51.100.7 port 51299 ssh2")
	ev := w.Read(context.Background(), sys, start.Add(time.Minute))
	if len(ev) != 2 {
		t.Fatalf("events = %+v", ev)
	}
	if e := ev[1]; e.Kind != "signin" || e.Subject != "root" || e.Address != "203.0.113.9" || e.Detail != "password" || e.At == "" {
		t.Errorf("root sign-in = %+v", e)
	}
	if !strings.Contains(strings.Join(j.args, " "), "--identifier=sshd-session") {
		t.Errorf("asked %v", j.args)
	}
	// Nothing new: nothing sent.
	if ev := w.Read(context.Background(), sys, start.Add(2*time.Minute)); len(ev) != 0 {
		t.Fatalf("sent again: %+v", ev)
	}
	// A restart remembers what was seen.
	again := &SigninWatch{Path: path}
	again.Read(context.Background(), sys, start.Add(3*time.Minute))
	j.add(start.Add(4*time.Minute), "Accepted publickey for ada from 198.51.100.7 port 1 ssh2")
	j.add(start.Add(4*time.Minute+time.Second), "Accepted publickey for ada from 192.0.2.44 port 2 ssh2")
	ev = again.Read(context.Background(), sys, start.Add(5*time.Minute))
	if len(ev) != 1 || ev[0].Address != "192.0.2.44" {
		t.Fatalf("after a restart: %+v", ev)
	}
}

func TestPrivateAddresses(t *testing.T) {
	for addr, want := range map[string]bool{"10.0.0.4": true, "192.168.1.9": true, "127.0.0.1": true, "::1": true, "100.64.3.2": true, "198.51.100.7": false, "2001:db8::1": false} {
		if Private(addr) != want {
			t.Errorf("%s: %v", addr, !want)
		}
	}
}
