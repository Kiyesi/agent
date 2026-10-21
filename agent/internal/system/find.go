package system

import (
	"errors"
	"os"
	"path/filepath"
)

// ProgramDirs are the only folders a program Kiyesi runs is taken from, in
// this order. They belong to root on every system Kiyesi supports. PATH is
// not used, so a folder someone put first in it cannot hand Kiyesi, running
// as root, a program of their own. /usr/local comes last, for tools such as
// Trivy and gitleaks that their installers put there.
var ProgramDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// ErrNoProgram is returned by Find when no folder holds the program.
var ErrNoProgram = errors.New("not installed")

// Find returns the full path of a program in ProgramDirs.
func Find(name string) (string, error) {
	if name == "" || filepath.Base(name) != name {
		return "", ErrNoProgram
	}
	for _, d := range ProgramDirs {
		p := filepath.Join(d, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", ErrNoProgram
}
