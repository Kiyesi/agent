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
	"path/filepath"
	"regexp"
	"sort"
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

// Take reads the records waiting in the spool, oldest first, at most 50 (a
// batch holds 100 items),
// and removes them. A file that cannot be read is removed too.
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
		data, err := readSmall(p)
		_ = os.Remove(p)
		var r Run
		if err != nil || json.Unmarshal(data, &r) != nil || !NamePattern.MatchString(r.Name) || r.RunID == "" {
			continue
		}
		out = append(out, r)
		if len(out) == 50 {
			break
		}
	}
	return out
}

func readSmall(p string) ([]byte, error) {
	// Never follow a link: a user could point one at a file only root reads.
	if info, err := os.Lstat(p); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(p) // #nosec G304 -- a file in the agent's own spool folder
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, errors.New("not a small regular file")
	}
	return io.ReadAll(io.LimitReader(f, 64*1024))
}
