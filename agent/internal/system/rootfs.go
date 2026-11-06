package system

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"

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

// Open opens a file; a large one, once closed, is not kept in the system's
// cache on the agent's account (see dropCache).
func (r RootFS) Open(name string) (fs.File, error) {
	f, err := r.dirFS().Open(name)
	if err != nil {
		return nil, err
	}
	if of, ok := f.(*os.File); ok {
		return lightFile{of}, nil
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

// lightFile drops a large file's cached pages when the agent is done with it.
type lightFile struct{ *os.File }

// cacheFrom is the size from which a file read once is not kept cached:
// logs, lockfiles, files searched for secrets. Smaller files, such as the
// settings other programs read too, are left as they are.
const cacheFrom = 256 << 10

func (f lightFile) Close() error {
	if info, err := f.File.Stat(); err == nil && info.Mode().IsRegular() && info.Size() >= cacheFrom {
		dropCache(f.File)
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
	return lightFile{f}, nil
}
