package system

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// KilledRE matches the kernel's line for a process killed for memory, both
// for the whole server and for a container's memory limit.
var KilledRE = regexp.MustCompile(`Killed process (\d+) \(([^)]+)\)`)

// OwnLimitRE matches the kernel's line just before a kill made by the
// kiyesi service's own memory limit, naming that limit's control group and
// the process: "oom-kill:constraint=CONSTRAINT_MEMCG,...,
// oom_memcg=/system.slice/kiyesi.service,...,task=apt-get,pid=4211,...".
var OwnLimitRE = regexp.MustCompile(`oom-kill:.*oom_memcg=[^,]*/kiyesi\.service,.*pid=(\d+)`)

// KillsKept is how long a kill stays in the record.
const KillsKept = 24 * time.Hour

// Kill is one process the kernel killed for memory.
type Kill struct {
	Process string    `json:"process"`
	At      time.Time `json:"at"`
}

// killFile is the record as written: since when the agent has watched,
// and the kills of the last 24 hours.
type killFile struct {
	Since time.Time `json:"since"`
	Kills []Kill    `json:"kills"`
}

// KillLog is the background agent's record of memory kills, taken from the
// system log's follower as they happen, so the memory check never searches
// the log: on a busy server a search for kernel lines reads the whole
// journal, gigabytes, whatever its filters (decisions log, 2026-11-08). The
// collector is its only writer.
type KillLog struct{ Path string }

// Load returns since when the agent has watched and the kills of the 24
// hours before now. A zero since means the agent has not watched yet.
func (l KillLog) Load(now time.Time) (time.Time, []Kill, error) {
	f, err := l.read()
	if err != nil {
		return time.Time{}, nil, err
	}
	return f.Since, recent(f.Kills, now), nil
}

// Record adds kills and notes that the agent watches from now on. It
// writes only when something changed: a new kill, or the first watch.
func (l KillLog) Record(now time.Time, kills []Kill) error {
	f, err := l.read()
	if err != nil {
		f = killFile{}
	}
	changed := f.Since.IsZero()
	if changed {
		f.Since = now.UTC()
	}
	for _, k := range kills {
		k.At = k.At.UTC()
		if !hasKill(f.Kills, k) {
			f.Kills = append(f.Kills, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	f.Kills = recent(f.Kills, now)
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return err
	}
	tmp := l.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.Path)
}

func (l KillLog) read() (killFile, error) {
	var f killFile
	data, err := os.ReadFile(l.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if json.Unmarshal(data, &f) != nil {
		return killFile{}, nil // a damaged record is started again
	}
	return f, nil
}

func hasKill(list []Kill, k Kill) bool {
	for _, x := range list {
		if x.Process == k.Process && x.At.Equal(k.At) {
			return true
		}
	}
	return false
}

func recent(list []Kill, now time.Time) []Kill {
	out := []Kill{}
	for _, k := range list {
		if now.Sub(k.At) <= KillsKept && !k.At.After(now.Add(time.Minute)) {
			out = append(out, k)
		}
	}
	return out
}
