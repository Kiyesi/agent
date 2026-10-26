// Package jobs watches timed jobs (PRD feature 23): the job runs on its own,
// from cron or a systemd timer, kiyesi job done records how each run went,
// and the agent finds each job's schedule and sends both. Kiyesi never
// starts a job.
package jobs

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/osfile"
)

// Run is one run of a job, as kiyesi job done records it: when it started and
// ended, and its exit code. Agents before 0.40.0 (kiyesi run) also recorded a
// start of its own and the last lines of output.
type Run struct {
	Name       string   `json:"name"`
	RunID      string   `json:"run_id"`
	StartedAt  string   `json:"started_at"`
	EndedAt    string   `json:"ended_at,omitempty"`
	ExitCode   *int     `json:"exit_code,omitempty"`
	DurationMs *int64   `json:"duration_ms,omitempty"`
	LastLines  []string `json:"last_lines,omitempty"`
	User       string   `json:"user,omitempty"`
}

// NamePattern is what a job's name may be: letters, digits, dots, dashes
// and underscores.
var NamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)

// RecordStart notes that a job just started on its own, from its crontab or
// timer, so a run that never starts is called missed and one still going
// long after its usual time is called running long. It starts nothing.
func RecordStart(spool, name string, now time.Time, newID func() string) error {
	run := Run{Name: name, RunID: newID(), StartedAt: now.UTC().Format(time.RFC3339Nano), User: os.Getenv("USER")}
	return write(spool, run.RunID+".start.json", run)
}

// Record notes one finished run of a job: the job itself ran on its own,
// from its crontab or timer, and Kiyesi only writes down how it went, in the
// spool folder for the agent to send. It never starts anything. started is
// when the job began, when known; otherwise the run is noted at its end, and
// the service joins it to the job's start that kiyesi job start noted.
func Record(spool, name string, code int, started, ended time.Time, newID func() string) error {
	if started.IsZero() || started.After(ended) {
		started = ended
	}
	ms := ended.Sub(started).Milliseconds()
	run := Run{
		Name: name, RunID: newID(),
		StartedAt: started.UTC().Format(time.RFC3339Nano), EndedAt: ended.UTC().Format(time.RFC3339Nano),
		ExitCode: &code, DurationMs: &ms, User: os.Getenv("USER"),
	}
	return write(spool, run.RunID+".end.json", run)
}

// write puts a record in the spool atomically: a hidden file, then renamed.
func write(spool, file string, r Run) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(spool, ".run-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	// The file stays private to the job's user (0600): the agent reads it as root.
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(spool, file)); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// PrepareSpool makes the folder kiyesi job done writes to: anyone may add a file,
// nobody may list it or remove another's file. Its parent becomes passable
// (not readable) so jobs running as other users can reach it. Only the agent,
// as root, calls it.
func PrepareSpool(state string) (string, error) {
	spool := filepath.Join(state, "runs")
	if err := os.MkdirAll(spool, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(state, 0o711); err != nil { // #nosec G302 -- passable, not readable, so other users can reach runs/
		return "", err
	}
	if err := os.Chmod(spool, 0o733|os.ModeSticky); err != nil { // #nosec G302 -- write-only drop folder with the sticky bit
		return "", err
	}
	return spool, nil
}

// perUser caps how many files of one user Take reads in one go, and how
// many of their runs it returns, so one user filling the spool cannot
// crowd out everyone else's runs. Their other files wait for the next go.
const (
	perUserReads = 200
	perUserRuns  = 25
)

// Take reads the records waiting in the spool, oldest first, at most 50 (a
// batch holds 100 items),
// and removes them. A file that cannot be read is removed too. A run's user
// is whoever owns its file, not what the file says, so nobody can record a
// run as someone else.
func Take(spool string) []Run {
	entries, err := os.ReadDir(spool)
	if err != nil {
		return nil
	}
	// A run's start before its end: by name, "end" would sort first.
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i].Name(), entries[j].Name()
		ka := strings.Replace(a, ".start.json", ".0.json", 1)
		kb := strings.Replace(b, ".start.json", ".0.json", 1)
		return ka < kb
	})
	var out []Run
	reads := map[uint32]int{}
	runs := map[uint32]int{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			// A half-written file older than an hour is left over: remove it.
			if info, err := e.Info(); err == nil && strings.HasPrefix(n, ".run-") && time.Since(info.ModTime()) > time.Hour {
				_ = os.Remove(filepath.Join(spool, n))
			}
			continue
		}
		p := filepath.Join(spool, n)
		if uid, ok := ownerOf(e); ok && (reads[uid] >= perUserReads || runs[uid] >= perUserRuns) {
			continue
		}
		data, uid, err := readSmall(p)
		_ = os.Remove(p)
		reads[uid]++
		var r Run
		if err != nil || json.Unmarshal(data, &r) != nil || !NamePattern.MatchString(r.Name) || r.RunID == "" {
			continue
		}
		r.User = userName(uid)
		runs[uid]++
		out = append(out, r)
		if len(out) == 50 {
			break
		}
	}
	return out
}

// readSmall reads a spool file and says who owns it. It never follows a
// link, as a user could point one at a file only root reads, and never
// waits on a pipe.
func readSmall(p string) ([]byte, uint32, error) {
	f, err := os.OpenFile(p, osfile.NoFollow, 0) // #nosec G304 -- a file in the agent's own spool folder
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	uid, _ := ownerOfInfo(info)
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, uid, errors.New("not a small regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024))
	return data, uid, err
}

func ownerOf(e os.DirEntry) (uint32, bool) {
	info, err := e.Info()
	if err != nil {
		return 0, false
	}
	return ownerOfInfo(info)
}

func ownerOfInfo(info os.FileInfo) (uint32, bool) {
	uid, _, _, ok := osfile.Owner(info)
	return uid, ok
}

// userName is the login name of uid, or the number when it has none.
func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return u.Username
	}
	return id
}
