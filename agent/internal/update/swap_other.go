//go:build !windows

package update

import "os"

// swap puts the new program in place of the old one in one step.
func swap(newPath, exe string) error { return os.Rename(newPath, exe) }
