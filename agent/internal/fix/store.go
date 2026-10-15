package fix

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Record is one fix that ran: what it changed and how to put it back.
type Record struct {
	ID   string    `json:"id"`
	Fix  string    `json:"fix"`
	Done string    `json:"done"`
	User string    `json:"user"`
	At   time.Time `json:"at"`
	// CanUndo is false for a change that cannot be taken back.
	CanUndo bool `json:"can_undo"`
	// Files are saved before they changed, in the order they changed.
	Files []Saved `json:"files,omitempty"`
	// Then are run after the files are back, in order, such as reloading SSH.
	Then     [][]string `json:"then,omitempty"`
	UndoneAt *time.Time `json:"undone_at,omitempty"`
}

// Saved is a file as it was before a fix touched it. Content is kept only
// for settings files a fix rewrites, never for a file whose mode alone
// changed, so a secret's value is never copied.
type Saved struct {
	Path     string      `json:"path"`
	Existed  bool        `json:"existed"`
	Mode     fs.FileMode `json:"mode"`
	Content  []byte      `json:"content,omitempty"`
	ModeOnly bool        `json:"mode_only,omitempty"`
}

// Store keeps the records in one folder that only root can read.
type Store struct {
	Dir string
	Now func() time.Time
}

// DefaultDir is where the records live.
const DefaultDir = "/var/lib/kiyesi/fixes"

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) dirOf(id string) string { return filepath.Join(s.Dir, id) }

// Begin starts a record with a new short id, such as 7f3a.
func (s *Store) Begin(fix, done, user string, canUndo bool) (*Record, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	for range 20 {
		b := make([]byte, 2)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		id := hex.EncodeToString(b)
		if err := os.Mkdir(s.dirOf(id), 0o700); err == nil {
			return &Record{ID: id, Fix: fix, Done: done, User: user, At: s.now().UTC(), CanUndo: canUndo}, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("no free record id")
}

func (s *Store) save(r *Record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dirOf(r.ID), ".record.json")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dirOf(r.ID), "record.json"))
}

func (s *Store) forget(id string) { _ = os.RemoveAll(s.dirOf(id)) }

// Get reads one record.
func (s *Store) Get(id string) (*Record, error) {
	if len(id) != 4 || strings.Trim(id, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("%q is not a fix id: they look like 7f3a", id)
	}
	data, err := os.ReadFile(filepath.Join(s.dirOf(id), "record.json")) // #nosec G304 -- id is checked above
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no fix %s on this server. See them with: sudo kiyesi fix undo", id)
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("the record of fix %s is damaged: %w", id, err)
	}
	return &r, nil
}

// List returns every record, newest first.
func (s *Store) List() ([]Record, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if r, err := s.Get(e.Name()); err == nil {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

// Undo puts back what a fix changed and marks it undone.
func (s *Store) Undo(ctx context.Context, h Host, r *Record) error {
	if r.UndoneAt != nil {
		return fmt.Errorf("fix %s was undone already, on %s", r.ID, r.UndoneAt.Local().Format("2 Jan 15:04"))
	}
	if !r.CanUndo {
		return fmt.Errorf("fix %s (%s) cannot be undone", r.ID, r.Done)
	}
	if err := undo(ctx, h, s, r); err != nil {
		return err
	}
	at := s.now().UTC()
	r.UndoneAt = &at
	return s.save(r)
}

// undo restores the files, newest change first, then runs the record's
// commands. It goes on after a failure, so as much as possible is back.
func undo(ctx context.Context, h Host, _ *Store, r *Record) error {
	var problems []string
	for i := len(r.Files) - 1; i >= 0; i-- {
		f := r.Files[i]
		var err error
		switch {
		case f.ModeOnly:
			err = h.Chmod(f.Path, f.Mode)
		case !f.Existed:
			err = h.Remove(f.Path)
		default:
			err = h.WriteFile(f.Path, f.Content, f.Mode)
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", f.Path, err))
		}
	}
	for _, c := range r.Then {
		if len(c) == 0 {
			continue
		}
		if _, err := h.Run(ctx, c[0], c[1:]...); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Changes is how a fix changes the server: each change is saved in the
// record first.
type Changes struct {
	h   Host
	s   *Store
	rec *Record
}

func (c *Changes) seen(path string) bool {
	for _, f := range c.rec.Files {
		if f.Path == path {
			return true
		}
	}
	return false
}

// keep saves a settings file as it is now, or that it was not there.
func (c *Changes) keep(path string) error {
	if c.seen(path) {
		return nil
	}
	info, err := c.h.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.rec.Files = append(c.rec.Files, Saved{Path: path})
	case err != nil:
		return err
	case !info.Mode().IsRegular():
		return fmt.Errorf("%s is not a plain file, so it is left alone", path)
	default:
		data, err := c.h.ReadFile(path)
		if err != nil {
			return err
		}
		c.rec.Files = append(c.rec.Files, Saved{Path: path, Existed: true, Mode: info.Mode().Perm(), Content: data})
	}
	// Saved at once, so even a crash leaves what undo needs.
	return c.s.save(c.rec)
}

// Keep saves a file a program is about to change, such as ufw's rules.
func (c *Changes) Keep(path string) error { return c.keep(path) }

// Write saves the file as it is, then writes the new one.
func (c *Changes) Write(path string, data []byte, perm fs.FileMode) error {
	if err := c.keep(path); err != nil {
		return err
	}
	return c.h.WriteFile(path, data, perm)
}

// Chmod saves the file's mode, never its content, then changes the mode.
func (c *Changes) Chmod(path string, perm fs.FileMode) error {
	info, err := c.h.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file, so it is left alone", path)
	}
	if !c.seen(path) {
		c.rec.Files = append(c.rec.Files, Saved{Path: path, Existed: true, Mode: info.Mode().Perm(), ModeOnly: true})
		if err := c.s.save(c.rec); err != nil {
			return err
		}
	}
	return c.h.Chmod(path, perm)
}

// Then adds a command undo runs after the files are back.
func (c *Changes) Then(name string, args ...string) error {
	c.rec.Then = append(c.rec.Then, append([]string{name}, args...))
	return c.s.save(c.rec)
}

// Run runs a program as part of the fix.
func (c *Changes) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return c.h.Run(ctx, name, args...)
}
