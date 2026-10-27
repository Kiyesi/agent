// Package version holds the agent's version. The number is raised in the
// pull request that changes the agent; builds add the git commit with
// -ldflags "-X github.com/kiyesi/kiyesi/agent/internal/version.Commit=...".
package version

import "strings"

// Version is the full version, such as 0.19.0.
var Version = "0.42.1"

// Commit is the git commit the binary was built from, when the build says.
var Commit = ""

// Short returns the major and minor version, such as 0.5, for the report header.
func Short() string {
	v := strings.TrimPrefix(Version, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// Full is the version with the commit, such as "0.5.0 (9a3dbcd)".
func Full() string {
	if Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}
