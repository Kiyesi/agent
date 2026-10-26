package keys

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Removal is one file a key is in, with its exact lines, for the commands
// kiyesi keys remove shows a person. Kiyesi changes no file.
type Removal struct {
	Account Account
	Path    string
	Lines   []string
}

// Plan finds every line that holds the key, file by file.
func Plan(fsys fs.FS, fingerprint string) []Removal {
	var out []Removal
	seen := map[string]bool{}
	for _, a := range Accounts(fsys) {
		for _, f := range Files {
			p := filepath.Join(a.Home, f)
			if seen[p] {
				continue
			}
			seen[p] = true
			data, _, err := readPlain(fsys, strings.TrimPrefix(p, "/"))
			if err != nil {
				continue
			}
			var lines []string
			for _, line := range strings.Split(string(data), "\n") {
				if k, ok := ParseLine(line); ok && k.Fingerprint == fingerprint {
					lines = append(lines, line)
				}
			}
			if len(lines) > 0 {
				out = append(out, Removal{Account: a, Path: p, Lines: lines})
			}
		}
	}
	return out
}
