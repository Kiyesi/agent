// Package system is the scan's only way to look at the server. Every read
// goes through it, so tests can hand the checks saved copies of real system
// files, and so it is easy to see that nothing here changes the server.
package system

import (
	"context"
	"errors"
	"io/fs"
	"time"
)

// ErrNeedsRoot means the data exists but only root (or a group the user is
// not in) can read it.
var ErrNeedsRoot = errors.New("needs root")

// System is everything a check may read.
type System struct {
	// FS is the server's file system, rooted at "/". Paths have no leading
	// slash, as io/fs requires: "proc/loadavg".
	FS fs.FS
	// Exec runs a read-only command from an allowlist.
	Exec Runner
	// Docker reads containers, or is nil when Docker is not installed.
	Docker Docker
	// Metadata reads the cloud provider's metadata address, or is nil.
	Metadata Metadata
	// Statfs reports the space and inodes of a mounted file system.
	Statfs func(path string) (Usage, error)
	// State keeps what the scan has seen before, such as when a security
	// update first appeared. It is the scan's own file, not the server's.
	State State
	// Now is the current time.
	Now func() time.Time
	// Root is true when the scan runs as root.
	Root bool
	// OS names the system, such as "Ubuntu 22.04".
	OS OSInfo
	// Hostname is the server's name.
	Hostname string
}

// OSInfo names the operating system from /etc/os-release.
type OSInfo struct {
	ID        string // ubuntu, debian, ...
	VersionID string // 22.04
	Name      string // Ubuntu 22.04
	Tested    bool   // true for the systems the pipeline tests on
}

// Usage is the space and inodes of one file system.
type Usage struct {
	TotalBytes, FreeBytes, AvailBytes uint64
	TotalInodes, FreeInodes           uint64
}

// Runner runs a command and returns what it printed on standard output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// Has reports whether the command is installed.
	Has(name string) bool
}

// State stores small facts between scans.
type State interface {
	Load() (map[string]string, error)
	Save(map[string]string) error
}
