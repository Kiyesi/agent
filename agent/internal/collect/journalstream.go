package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// One journalctl --follow, kept running, instead of three journalctl runs
// each minute (decisions log, 2026-11-06): on a small server those runs
// read through the journal's files again and again, and with their cache
// kept the agent's service at a fifth of a CPU and its memory limit.
// journald's own filters pick the lines, so only what is needed reaches the
// agent: warnings and errors, your own services, and SSH sign-ins.

// streamBuffer is the most entries kept between two minutes; past it the
// oldest go, and the next minute says how many.
const streamBuffer = 5000

type journalStream struct {
	mu      sync.Mutex
	entries []journalEntry
	dropped int
	// key is the filter the running follower was started with.
	key     string
	running bool
	cancel  context.CancelFunc
	// retryAt is when a follower that stopped may be started again.
	retryAt time.Time
}

// streamArgs are the follower's arguments: only new entries, as JSON, with
// the fields the agent reads, and journald's own matches (the same field is
// "or"; "+" starts another set): warnings and worse, your units, and SSH.
func streamArgs(units []string) []string {
	args := []string{
		"--follow", "--lines=0", "--output=json", "--no-pager", "--quiet",
		"--output-fields=" + journalFields,
		"PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3", "PRIORITY=4",
	}
	for _, u := range units {
		args = append(args, "+", "_SYSTEMD_UNIT="+u)
	}
	return append(args, "+", "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session")
}

// ensure keeps a follower running for these units, starting or restarting
// it as needed, and says whether one runs. A follower that stopped is
// started again after 30 seconds.
func (s *journalStream) ensure(sys *system.System, units []string, now time.Time) bool {
	st, ok := sys.Exec.(system.Streamer)
	if !ok || !sys.Exec.Has("journalctl") {
		return false
	}
	sort.Strings(units)
	key := strings.Join(units, ",")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running && s.key == key {
		return true
	}
	if s.running {
		s.cancel()
		s.running = false
	}
	if now.Before(s.retryAt) {
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	out, wait, err := st.Stream(ctx, "journalctl", streamArgs(units)...)
	if err != nil {
		cancel()
		s.retryAt = now.Add(30 * time.Second)
		return false
	}
	s.key, s.running, s.cancel = key, true, cancel
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var e journalEntry
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			s.mu.Lock()
			if len(s.entries) >= streamBuffer {
				s.entries = s.entries[1:]
				s.dropped++
			}
			s.entries = append(s.entries, e)
			s.mu.Unlock()
		}
		_ = out.Close()
		_ = wait()
		s.mu.Lock()
		if s.key == key {
			s.running = false
			s.retryAt = time.Now().Add(30 * time.Second)
		}
		s.mu.Unlock()
		cancel()
	}()
	return true
}

// take hands over the entries read since the last minute, oldest first.
func (s *journalStream) take() []journalEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.entries
	s.entries = nil
	s.dropped = 0
	return out
}

// fromStream is the sign-in watch reading the follower's SSH lines.
func (w *SigninWatch) fromStream(entries []journalEntry, now time.Time) []Event {
	if w.seen == nil {
		w.seen = w.load()
	}
	if w.since == 0 {
		w.since = now.UnixMicro()
	}
	var events []Event
	changed := false
	for _, e := range entries {
		if e.Identifier != "sshd" && e.Identifier != "sshd-session" {
			continue
		}
		usec, err := strconv.ParseInt(e.Realtime, 10, 64)
		if err != nil {
			continue
		}
		msg, _ := e.Message.(string)
		if ev, ok := w.accept(msg, usec); ok {
			events = append(events, ev)
		}
		changed = true
	}
	if changed {
		w.save()
	}
	return events
}
