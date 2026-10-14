//go:build linux

package system

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Statfs reads the space and inodes of the file system at path.
func Statfs(path string) (Usage, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return Usage{}, err
	}
	if s.Bsize <= 0 {
		return Usage{}, errors.New("the file system reported no block size")
	}
	bs := uint64(s.Bsize) // #nosec G115 -- checked above to be positive
	return Usage{
		TotalBytes:  s.Blocks * bs,
		FreeBytes:   s.Bfree * bs,
		AvailBytes:  s.Bavail * bs,
		TotalInodes: s.Files,
		FreeInodes:  s.Ffree,
	}, nil
}
