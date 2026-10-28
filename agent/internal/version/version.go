// Package version holds the agent's version. The number is raised in the
// pull request that changes the agent; builds add the git commit with
// -ldflags "-X github.com/kiyesi/kiyesi/agent/internal/version.Commit=...".
package version

import "strings"

// Version is the full version, such as 0.19.0.
var Version = "0.44.0"

// Security is true in a release that fixes a security problem. The release
// writes "security yes" into its signed list, so kiyesi on every server and
// the service can say so, and the owners of servers on older versions are
// emailed once. Set it in the pull request that makes such a fix.
const Security = false

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
