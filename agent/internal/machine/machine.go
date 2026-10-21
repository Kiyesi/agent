// Package machine gives a one-way hash of this server's machine ID, so the
// service can tell when the same server is connected more than once. The ID
// itself never leaves the server: only the hash is sent.
package machine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

// Paths are where the machine ID is read from, in order: systemd's file,
// then the older D-Bus one. Tests change them.
var Paths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// prefix keeps this hash apart from any other made from the same ID.
const prefix = "kiyesi-machine-v1:"

var (
	once   sync.Once
	cached string
)

// Hash returns the hash of the machine ID, read once and kept, or "" when
// no machine ID can be read.
func Hash() string {
	once.Do(func() { cached = HashFrom(Paths) })
	return cached
}

// HashFrom reads the first of paths that holds a machine ID and returns its
// hash as 64 lowercase hex characters. A file that cannot be read, or that
// does not hold 32 hex characters, is skipped; with none left it returns "".
func HashFrom(paths []string) string {
	for _, p := range paths {
		raw, err := os.ReadFile(p) // #nosec G304 -- a fixed system path, or one a test gives
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(raw)); valid(id) {
			return Of(id)
		}
	}
	return ""
}

// Of returns the hash of one machine ID.
func Of(id string) string {
	sum := sha256.Sum256([]byte(prefix + id))
	return hex.EncodeToString(sum[:])
}

// valid says whether id is a machine ID: 32 hex characters.
func valid(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
