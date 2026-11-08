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
// "or"; "+" starts another set, and different fields in one set must all
// match): warnings and worse, your units, SSH, and the kernel's info lines,
// which carry the line naming the memory limit behind a kill.
func streamArgs(units []string) []string {
	args := []string{
		"--follow", "--lines=0", "--output=json", "--no-pager", "--quiet",
		"--output-fields=" + journalFields,
		"PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3", "PRIORITY=4",
	}
	for _, u := range units {
		args = append(args, "+", "_SYSTEMD_UNIT="+u)
	}
	return append(args, "+", "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session",
		"+", "_TRANSPORT=kernel", "PRIORITY=6")
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
			if json.Unmarshal(sc.Bytes(), &e) != nil || !wanted(e) {
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

// wanted drops the kernel's info lines other than the one naming the
// memory limit behind a kill, before they take room in the buffer: some
// servers write many.
func wanted(e journalEntry) bool {
	if e.Transport != "kernel" || e.Priority != "6" {
		return true
	}
	msg, _ := e.Message.(string)
	return strings.HasPrefix(strings.TrimSpace(msg), "oom-kill:")
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

// killWatch turns the follower's kernel lines into the record of memory
// kills the memory check reads. A kill made by the kiyesi service's own
// memory limit is left out: the kernel names that limit in the line just
// before, which may come in the minute before.
type killWatch struct {
	own map[string]time.Time // pid -> when its limit line was seen
}

func (w *killWatch) fromStream(entries []journalEntry, log *system.KillLog, now time.Time) {
	if w.own == nil {
		w.own = map[string]time.Time{}
	}
	for pid, at := range w.own {
		if now.Sub(at) > 10*time.Minute {
			delete(w.own, pid)
		}
	}
	var kills []system.Kill
	for _, e := range entries {
		msg, ok := e.Message.(string)
		if !ok || e.Transport != "kernel" {
			continue
		}
		if m := system.OwnLimitRE.FindStringSubmatch(msg); m != nil {
			w.own[m[1]] = now
			continue
		}
		m := system.KilledRE.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		if _, own := w.own[m[1]]; own {
			continue
		}
		usec, err := strconv.ParseInt(e.Realtime, 10, 64)
		if err != nil {
			continue
		}
		kills = append(kills, system.Kill{Process: m[2], At: time.UnixMicro(usec).UTC()})
	}
	_ = log.Record(now, kills)
}
