package system

import (
	"os"

	"golang.org/x/sys/unix"
)

// dropCache tells Linux the agent will not read this file again soon, so
// its pages are not kept in the cache on the agent's service's account:
// read once by a check, they would otherwise sit in its memory as cache.
// Only clean pages go; nothing the file's own program wrote is lost.
func dropCache(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
