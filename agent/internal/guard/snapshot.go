// Package guard is kiyesi guard: a seatbelt for a risky change. Before a
// command runs, it saves a copy of the server's settings (/etc) and notes
// what works: the grade, the services that run, the containers, and the
// server's own sites. After, it checks them again, says what changed, and
// when something broke offers to put the settings back. The copy stays on
// the server, readable by root only, and is never sent. Package upgrades
// cannot be reliably reversed, so they are listed with the commands to go
// back, never undone by themselves.
package guard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// DefaultDir is where each guarded run keeps its copy.
const DefaultDir = "/var/lib/kiyesi/guard"

// Keep is how many guarded runs are kept; older ones are removed.
const Keep = 5

// maxFile and maxTotal cap the copy: /etc holds settings, not data.
const (
	maxFile  = 4 << 20
	maxTotal = 256 << 20
)

// secret files are never copied: password hashes and private keys stay
// only where they are. A change to them is noted, never put back.
var secretNames = map[string]bool{
	"shadow": true, "shadow-": true, "gshadow": true, "gshadow-": true,
	"opasswd": true, "master.passwd": true,
}

var secretDirs = []string{"ssl/private/", "letsencrypt/", "pki/tls/private/", "kiyesi/"}

// Secret says whether a file under /etc, by its path inside /etc, is one
// that holds a password or a private key, so it is never copied.
func Secret(rel string) bool {
	if secretNames[filepath.Base(rel)] {
		return true
	}
	for _, d := range secretDirs {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	base := filepath.Base(rel)
	return strings.HasSuffix(base, ".key") ||
		(strings.HasPrefix(rel, "ssh/ssh_host_") && strings.HasSuffix(base, "_key"))
}

// File is one settings file as it was.
type File struct {
	Path string      `json:"path"` // inside /etc, such as nginx/nginx.conf
	Mode fs.FileMode `json:"mode"`
	UID  int         `json:"uid"`
	GID  int         `json:"gid"`
	Size int64       `json:"size"`
	Sum  string      `json:"sum"`
	// Kept is false for a secret or an oversized file: noted, not copied.
	Kept bool `json:"kept"`
	// Link is set on a symbolic link, with where it points.
	Link string `json:"link,omitempty"`
}

// Manifest is everything one guarded run noted before the command.
type Manifest struct {
	ID       string    `json:"id"`
	Command  []string  `json:"command"`
	User     string    `json:"user"`
	At       time.Time `json:"at"`
	Root     string    `json:"root"` // the folder copied, /etc
	Files    []File    `json:"files"`
	Packages []string  `json:"packages"` // "name version", sorted
	Before   State     `json:"before"`
	After    *State    `json:"after,omitempty"`
	Exit     *int      `json:"exit,omitempty"`
	// RestoredAt is when the settings were put back.
	RestoredAt *time.Time `json:"restored_at,omitempty"`
}

// State is what worked: the grade, failed services, running containers and
// the sites' answers.
type State struct {
	Letter     string         `json:"letter"`
	Score      int            `json:"score"`
	Failed     []string       `json:"failed"`
	Containers []string       `json:"containers"`
	Sites      map[string]int `json:"sites"` // address -> status, 0 for no answer
}

// Store keeps the guarded runs.
type Store struct{ Dir string }

func (s Store) dirOf(id string) string { return filepath.Join(s.Dir, id) }

// newID is a short id, such as 7f3a, not used yet.
func (s Store) newID() (string, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil { // #nosec G302 -- a folder: 0700 is root alone
		return "", err
	}
	for range 20 {
		b := make([]byte, 2)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		id := hex.EncodeToString(b)
		if err := os.Mkdir(s.dirOf(id), 0o700); err == nil {
			return id, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("no free id")
}

// Save writes the manifest.
func (s Store) Save(m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dirOf(m.ID), ".manifest.json")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dirOf(m.ID), "manifest.json"))
}

// Get reads one guarded run.
func (s Store) Get(id string) (*Manifest, error) {
	if len(id) != 4 || strings.Trim(id, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("%q is not a guard id: they look like 7f3a", id)
	}
	data, err := os.ReadFile(filepath.Join(s.dirOf(id), "manifest.json")) // #nosec G304 -- id is checked above
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no guarded run %s on this server. See them with: sudo kiyesi guard list", id)
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("the record of guarded run %s is damaged: %w", id, err)
	}
	return &m, nil
}

// List returns the guarded runs, newest first.
func (s Store) List() ([]Manifest, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if m, err := s.Get(e.Name()); err == nil {
			out = append(out, *m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

// Prune removes all but the newest Keep runs.
func (s Store) Prune() {
	list, err := s.List()
	if err != nil {
		return
	}
	for i, m := range list {
		if i >= Keep {
			_ = os.RemoveAll(s.dirOf(m.ID))
		}
	}
}

// Snapshot copies the settings under root (/etc) into a new guarded run.
func (s Store) Snapshot(root string, command []string, user string, now time.Time) (*Manifest, error) {
	id, err := s.newID()
	if err != nil {
		return nil, err
	}
	m := &Manifest{ID: id, Command: command, User: user, At: now.UTC(), Root: root}
	files, err := s.copyTree(root, filepath.Join(s.dirOf(id), "files"))
	if err != nil {
		_ = os.RemoveAll(s.dirOf(id))
		return nil, err
	}
	m.Files = files
	return m, s.Save(m)
}

// copyTree copies root's plain files and links into dest, noting each.
func (s Store) copyTree(root, dest string) ([]File, error) {
	var out []File
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // a folder that cannot be read is left out
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(p)
		if err != nil {
			return nil
		}
		st, _ := info.Sys().(*syscall.Stat_t)
		f := File{Path: rel, Mode: info.Mode()}
		if st != nil {
			f.UID, f.GID = int(st.Uid), int(st.Gid)
		}
		switch {
		case d.IsDir():
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return nil
			}
			f.Link, f.Kept = t, true
		case !info.Mode().IsRegular():
			return nil
		default:
			f.Size = info.Size()
			sum, err := fileSum(p)
			if err != nil {
				return nil
			}
			f.Sum = sum
			if !Secret(rel) && f.Size <= maxFile && total+f.Size <= maxTotal {
				if err := copyFile(p, filepath.Join(dest, filepath.FromSlash(rel))); err != nil {
					return fmt.Errorf("copying %s: %w", p, err)
				}
				total += f.Size
				f.Kept = true
			}
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

func fileSum(p string) (string, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- a file under /etc, read only
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxTotal)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	in, err := os.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- a file under /etc, read only
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- inside the guard's own folder
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, maxFile+1)); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Change is one settings file that differs from the copy.
type Change struct {
	Path string `json:"path"`
	// Kind is changed, added or removed.
	Kind string `json:"kind"`
	// Kept is false when it cannot be put back: a secret or a big file.
	Kept bool `json:"kept"`
}

// Changes compares the settings now with the copy.
func Changes(m *Manifest) []Change {
	now := map[string]File{}
	_ = filepath.WalkDir(m.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(m.Root, p)
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(p)
		if err != nil {
			return nil
		}
		f := File{Path: rel, Mode: info.Mode()}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			f.Link, _ = os.Readlink(p)
		case info.Mode().IsRegular():
			f.Sum, _ = fileSum(p)
		default:
			return nil
		}
		now[rel] = f
		return nil
	})
	was := map[string]File{}
	for _, f := range m.Files {
		was[f.Path] = f
	}
	var out []Change
	for _, f := range m.Files {
		n, ok := now[f.Path]
		switch {
		case !ok:
			out = append(out, Change{Path: f.Path, Kind: "removed", Kept: f.Kept})
		case n.Sum != f.Sum || n.Link != f.Link || n.Mode != f.Mode:
			out = append(out, Change{Path: f.Path, Kind: "changed", Kept: f.Kept})
		}
	}
	for p := range now {
		if _, ok := was[p]; !ok {
			out = append(out, Change{Path: p, Kind: "added", Kept: !Secret(p)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Restore puts the copied settings back as they were: changed and removed
// files from the copy, with their mode and owner, and files the command
// added taken away. Secrets and big files, never copied, are left as they
// are now and named in the error.
func (s Store) Restore(m *Manifest, changes []Change) (restored int, left []string, err error) {
	byPath := map[string]File{}
	for _, f := range m.Files {
		byPath[f.Path] = f
	}
	var problems []string
	for _, c := range changes {
		target := filepath.Join(m.Root, filepath.FromSlash(c.Path))
		if !strings.HasPrefix(target, m.Root+string(filepath.Separator)) {
			continue
		}
		if !c.Kept {
			left = append(left, c.Path)
			continue
		}
		var e error
		switch c.Kind {
		case "added":
			if info, err := os.Lstat(target); err == nil && (info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0) {
				e = os.Remove(target)
			}
		default:
			e = s.put(m, byPath[c.Path], target)
		}
		if e != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", c.Path, e))
			continue
		}
		restored++
	}
	if len(problems) > 0 {
		return restored, left, errors.New(strings.Join(problems, "; "))
	}
	return restored, left, nil
}

// put writes one file back from the copy, through a temporary file and a
// rename beside it, never through a link.
func (s Store) put(m *Manifest, f File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil { // #nosec G301 -- a folder under /etc that a command removed
		return err
	}
	if f.Link != "" {
		tmp := target + ".kiyesi-guard"
		_ = os.Remove(tmp)
		if err := os.Symlink(f.Link, tmp); err != nil {
			return err
		}
		return os.Rename(tmp, target)
	}
	data, err := os.ReadFile(filepath.Join(s.dirOf(m.ID), "files", filepath.FromSlash(f.Path))) // #nosec G304 -- the guard's own copy
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".kiyesi-guard-*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(f.Mode.Perm() | f.Mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)); err != nil {
		return err
	}
	if err := tmp.Chown(f.UID, f.GID); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return err
	}
	done = true
	return nil
}
