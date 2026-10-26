//go:build windows

package osfile

import (
	"os"
	"syscall"
)

// NoFollow is a plain read-only open: on Windows only the laptop commands
// run, never the server checks that need more.
const NoFollow = os.O_RDONLY

// Owner is never known on Windows, so server code that needs it refuses.
func Owner(os.FileInfo) (uid, gid uint32, links uint64, ok bool) { return 0, 0, 0, false }

// AsUser has no meaning on Windows.
func AsUser(uint32, uint32) *syscall.SysProcAttr { return nil }

// Identity is never known on Windows, so server code that needs it refuses.
func Identity(os.FileInfo) (dev, ino uint64, uid uint32, ok bool) { return 0, 0, 0, false }
