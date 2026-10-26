//go:build unix

// Package osfile holds the few file and process details that differ by
// system. The server checks and changes run on Linux; on Windows only the
// laptop commands run, and these give answers that make server code refuse.
package osfile

import (
	"os"
	"syscall"
)

// NoFollow opens read-only without following a link at the last step and
// without waiting on a pipe or a device.
const NoFollow = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_NOCTTY

// Owner is a file's owner, group and link count, when the system says.
func Owner(info os.FileInfo) (uid, gid uint32, links uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, uint64(st.Nlink), true // #nosec G115 -- a link count is never negative
}

// AsUser runs a process as that user and group, with no other groups.
func AsUser(uid, gid uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
}

// Identity is a file's device and inode, which name it on disk, and its
// owner, when the system says.
func Identity(info os.FileInfo) (dev, ino uint64, uid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, 0, false
	}
	return uint64(st.Dev), st.Ino, st.Uid, true // #nosec G115 -- a device number is never negative
}
