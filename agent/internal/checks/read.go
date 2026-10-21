package checks

import (
	"errors"
	"io"
	"io/fs"
)

// readCap is the most the scan reads of one user's file.
const readCap = 1 << 20

// errNotPlain is a path that is not a plain file now, such as a link swapped
// in after the folder was listed, or a pipe.
var errNotPlain = errors.New("not a plain file")

// errTooBig is a file over readCap, which the scan leaves alone.
var errTooBig = errors.New("too big to read")

// noFollowFS is a file system that can open a file without following a
// link at its last step, as system.RootFS does.
type noFollowFS interface {
	OpenNoFollow(name string) (fs.File, error)
}

// readUserFile reads a file a user controls, such as an .env: never through
// a link, only a plain file, and at most readCap bytes. Checks the open
// file, not the name, so nothing can be swapped in between.
func readUserFile(fsys fs.FS, name string) ([]byte, error) {
	var f fs.File
	var err error
	if nf, ok := fsys.(noFollowFS); ok {
		f, err = nf.OpenNoFollow(name)
	} else {
		f, err = fsys.Open(name)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotPlain
	}
	if info.Size() > readCap {
		return nil, errTooBig
	}
	return io.ReadAll(io.LimitReader(f, readCap))
}
