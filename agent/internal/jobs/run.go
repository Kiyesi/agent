// Package jobs watches timed jobs (PRD feature 23): kiyesi run records each
// run, and the agent finds each job's schedule and sends both.
package jobs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Run is one run of a job, as kiyesi run records it: a start, and later an
// end with the exit code, how long it took and its last lines of output.
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

const (
	keepLines   = 20
	maxLineSize = 500
)

// tail keeps the last lines written to it.
type tail struct {
	mu      sync.Mutex
	partial []byte
	lines   []string
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.partial = append(t.partial, p...)
	for {
		i := bytes.IndexByte(t.partial, '\n')
		if i < 0 {
			break
		}
		t.add(string(t.partial[:i]))
		t.partial = t.partial[i+1:]
	}
	// A very long line without an end is kept in part.
	if len(t.partial) > 64*1024 {
		t.add(string(t.partial[:maxLineSize]))
		t.partial = t.partial[:0]
	}
	return len(p), nil
}

func (t *tail) add(line string) {
	line = strings.TrimRight(line, "\r")
	if len(line) > maxLineSize {
		line = line[:maxLineSize] + "…"
	}
	t.lines = append(t.lines, line)
	if len(t.lines) > keepLines {
		t.lines = t.lines[len(t.lines)-keepLines:]
	}
}

func (t *tail) last() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.partial) > 0 {
		t.add(string(t.partial))
		t.partial = nil
	}
	return append([]string(nil), t.lines...)
}

// Execute runs the command as it would run without Kiyesi: the same input,
// output and exit code, signals passed on. It records the start and the end
// in the spool folder for the agent to send. Recording never fails or slows
// the job: when the folder cannot be written, the run is not recorded, and
// one line on stderr says so. An empty spool records nothing, silently: the
// caller has said why.
func Execute(spool, name string, args []string, stdin io.Reader, stdout, stderr io.Writer, newID func() string, now func() time.Time) int {
	id := newID()
	started := now()
	user := ""
	if u := os.Getenv("USER"); u != "" {
		user = u
	}
	run := Run{Name: name, RunID: id, StartedAt: started.UTC().Format(time.RFC3339Nano), User: user}
	record := func(file string) {
		if spool == "" {
			return
		}
		if err := write(spool, file, run); err != nil {
			_, _ = io.WriteString(stderr, "kiyesi run: this run is not recorded, so Kiyesi will not see it ("+err.Error()+"). Is the agent running? sudo systemctl status kiyesi\n")
			spool = "" // said once is enough
		}
	}
	record(id + ".start.json")

	out := &tail{}
	cmd := exec.Command(args[0], args[1:]...) // #nosec G204 -- the command is the user's own job, as they wrote it
	cmd.Stdin = stdin
	cmd.Stdout = io.MultiWriter(stdout, out)
	cmd.Stderr = io.MultiWriter(stderr, out)
	code := 0
	if err := cmd.Start(); err != nil {
		code = 127
		if errors.Is(err, os.ErrPermission) {
			code = 126
		}
		_, _ = io.WriteString(stderr, "kiyesi run: "+err.Error()+"\n")
		out.add(err.Error())
	} else {
		sigs := make(chan os.Signal, 4)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		go func() {
			for s := range sigs {
				_ = cmd.Process.Signal(s)
			}
		}()
		err := cmd.Wait()
		signal.Stop(sigs)
		close(sigs)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
			if code < 0 {
				code = 128 + int(exit.Sys().(syscall.WaitStatus).Signal())
			}
		} else if err != nil {
			code = 1
		}
	}
	ended := now()
	ms := ended.Sub(started).Milliseconds()
	run.EndedAt = ended.UTC().Format(time.RFC3339Nano)
	run.ExitCode = &code
	run.DurationMs = &ms
	run.LastLines = out.last()
	record(id + ".end.json")
	return code
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

// PrepareSpool makes the folder kiyesi run writes to: anyone may add a file,
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
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- a file in the agent's own spool folder
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return st.Uid, true
}

// userName is the login name of uid, or the number when it has none.
func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return u.Username
	}
	return id
}
