//go:build windows

package update

import (
	"errors"
	"io/fs"
	"os"
)

// swap puts the new program in place of the running one. Windows will not
// replace a running program, but lets it be renamed: the old one becomes
// kiyesi.exe.old, the new one takes its name, and the old one is put back
// if that fails. The next update removes the .old file.
func swap(newPath, exe string) error {
	old := exe + ".old"
	if err := os.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	return nil
}
