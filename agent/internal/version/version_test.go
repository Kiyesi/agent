package version

import (
	"regexp"
	"testing"
)

func TestVersionIsSemver(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Version) {
		t.Errorf("Version %q is not major.minor.patch", Version)
	}
}

func TestFullAddsTheCommit(t *testing.T) {
	old := Commit
	t.Cleanup(func() { Commit = old })
	Commit = ""
	if Full() != Version {
		t.Errorf("Full() = %q without a commit", Full())
	}
	Commit = "9a3dbcd"
	if Full() != Version+" (9a3dbcd)" {
		t.Errorf("Full() = %q", Full())
	}
}
