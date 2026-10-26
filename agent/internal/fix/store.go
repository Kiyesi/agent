package fix

import (
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

// Record is one change kiyesi fix made before 0.40.0: what it changed, and
// what undoes it.
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
	// Then are the steps after the files are back, in order, such as reloading SSH.
	Then [][]string `json:"then,omitempty"`
	// Keys are login keys kiyesi keys remove took out of users'
	// authorized_keys files.
	Keys     []KeyLines `json:"keys,omitempty"`
	UndoneAt *time.Time `json:"undone_at,omitempty"`
}

// KeyLines are the lines taken out of one authorized_keys file.
type KeyLines struct {
	User  string   `json:"user"`
	UID   int      `json:"uid"`
	GID   int      `json:"gid"`
	Home  string   `json:"home"`
	Path  string   `json:"path"`
	Lines []string `json:"lines"`
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
	// ID is the file a change of mode reached. Records from before 0.38.0
	// have none.
	ID *FileID `json:"id,omitempty"`
}

// FileID names one file on disk, as a record from 0.38.0 to 0.39.x noted
// it: its device, its inode and its owner.
type FileID struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
	UID uint32 `json:"uid"`
}

// Store reads the records kiyesi fix kept before 0.40.0, in one folder that
// only root can read. Nothing writes to it any more.
type Store struct{ Dir string }

// DefaultDir is where the records live.
const DefaultDir = "/var/lib/kiyesi/fixes"

func (s *Store) dirOf(id string) string { return filepath.Join(s.Dir, id) }

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
