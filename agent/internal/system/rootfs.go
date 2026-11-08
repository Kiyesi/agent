package system

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/osfile"
)

// RootFS is the machine's files from a folder, usually /, as os.DirFS gives
// them, and also opens a file without following a link at its last step.
// The scan reads users' own files through it, so a user cannot point one at
// a file only root may read, or at a pipe that never ends.
type RootFS struct{ Dir string }

// NewRootFS returns the files under dir.
func NewRootFS(dir string) RootFS { return RootFS{Dir: dir} }

func (r RootFS) dirFS() fs.FS { return os.DirFS(r.Dir) }

// Open opens a file; once closed, it is not kept in the system's cache on
// the agent's account (see dropCache), unless it is a shared setting.
func (r RootFS) Open(name string) (fs.File, error) {
	f, err := r.dirFS().Open(name)
	if err != nil {
		return nil, err
	}
	if of, ok := f.(*os.File); ok {
		return lightFile{of, keepCached(name)}, nil
	}
	return f, nil
}

func (r RootFS) ReadFile(name string) ([]byte, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// lightFile drops a file's cached pages when the agent is done with it:
// logs, lockfiles, package lists, programs compared with their packages,
// files searched for secrets. Read once a minute or once a scan, they would
// otherwise sit in the agent's service as cache, up to its memory limit.
type lightFile struct {
	*os.File
	keep bool
}

// keptCached are the folders whose files stay cached: /etc holds small
// settings that the server's own programs read all the time, and /proc,
// /sys, /dev and /run are not on disk, so there is nothing to drop.
var keptCached = []string{"etc/", "proc/", "sys/", "dev/", "run/"}

func keepCached(name string) bool {
	for _, p := range keptCached {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// drop is dropCache; a test watches it.
var drop = dropCache

func (f lightFile) Close() error {
	if !f.keep {
		if info, err := f.File.Stat(); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			drop(f.File)
		}
	}
	return f.File.Close()
}

// ReadDir lets fs.ReadDir list a directory opened through Open.
func (f lightFile) ReadDir(n int) ([]fs.DirEntry, error) { return f.File.ReadDir(n) }

func (r RootFS) ReadDir(name string) ([]fs.DirEntry, error) { return fs.ReadDir(r.dirFS(), name) }

func (r RootFS) Stat(name string) (fs.FileInfo, error) { return fs.Stat(r.dirFS(), name) }

// ReadLink returns where a link points, as the system says it, such as a
// process's program in /proc/<pid>/exe. Only read, never followed.
func (r RootFS) ReadLink(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	return os.Readlink(filepath.Join(r.Dir, filepath.FromSlash(name)))
}

// Lstat describes name itself, a link as a link.
func (r RootFS) Lstat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrInvalid}
	}
	return os.Lstat(filepath.Join(r.Dir, filepath.FromSlash(name)))
}

// OpenNoFollow opens name for reading, refusing a link at its last step and
// never waiting on a pipe or a device.
func (r RootFS) OpenNoFollow(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	f, err := os.OpenFile(filepath.Join(r.Dir, filepath.FromSlash(name)), osfile.NoFollow, 0) // #nosec G304 -- a path the scan found, opened read-only without following a link
	if err != nil {
		return nil, err
	}
	return lightFile{f, keepCached(name)}, nil
}
