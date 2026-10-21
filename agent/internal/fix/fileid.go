package fix

import (
	"fmt"
	"io/fs"
	"syscall"
)

// FileID names one file on disk: its device, its inode and its owner. A
// change of mode checks it first, so the change reaches the file Kiyesi
// looked at, never one a user swapped in later, such as a link to
// /etc/shadow.
type FileID struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
	UID uint32 `json:"uid"`
}

// IDOf reads the identity from what Lstat or Stat returned. ok is false
// when the system does not give one.
func IDOf(info fs.FileInfo) (id FileID, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return FileID{}, false
	}
	return FileID{Dev: uint64(st.Dev), Ino: st.Ino, UID: st.Uid}, true // #nosec G115 -- a device number is never negative
}

// ownerOf returns who owns a file or folder.
func ownerOf(info fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

// othersCanWrite says why a user other than root and the file's owner could
// add, remove or rename files in a folder, or "" when none can. Such a user
// could put a different file at the path between Kiyesi's look and its
// change; the identity check catches that, and this refuses even to try.
func othersCanWrite(dir fs.FileInfo, fileOwner uint32) string {
	uid, gid, ok := ownerOf(dir)
	if !ok {
		return "Kiyesi cannot tell who may write to its folder"
	}
	m := dir.Mode()
	switch {
	case m&0o002 != 0:
		return "its folder can be written to by every user"
	case m&0o020 != 0 && gid != 0:
		return fmt.Sprintf("its folder can be written to by group %d", gid)
	case m&0o200 != 0 && uid != 0 && uid != fileOwner:
		return fmt.Sprintf("its folder belongs to user %d, who does not own the file", uid)
	}
	return ""
}
