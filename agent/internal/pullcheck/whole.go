package pullcheck

import (
	"path"
	"regexp"
)

// wholeNames are the dependency files read whole, before and after: the
// manifests and lockfiles of the eight languages. The service's
// api/src/features/pullchecks/files.ts reads the same names from GitHub; a
// test keeps the two lists the same.
var wholeNames = map[string]bool{
	// npm
	"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"yarn.lock": true, "pnpm-lock.yaml": true, "bun.lock": true,
	// PyPI
	"requirements.txt": true, "Pipfile": true, "Pipfile.lock": true, "poetry.lock": true,
	"pyproject.toml": true, "uv.lock": true, "setup.py": true, "setup.cfg": true,
	// Go
	"go.mod": true, "go.sum": true,
	// Maven
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "gradle.lockfile": true,
	// RubyGems
	"Gemfile": true, "Gemfile.lock": true,
	// crates.io
	"Cargo.toml": true, "Cargo.lock": true,
	// NuGet
	"packages.config": true, "packages.lock.json": true, "Directory.Packages.props": true,
	// Packagist
	"composer.json": true, "composer.lock": true,
}

var wholePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^requirements[\w.-]*\.(txt|in)$`),
	regexp.MustCompile(`\.gemspec$`),
	regexp.MustCompile(`\.(cs|fs|vb)proj$`),
}

// ReadWhole says whether a changed file is given to Check whole, before and
// after (a dependency file or a workflow), rather than as its patch alone.
// The path is the repository's, with forward slashes.
func ReadWhole(p string) bool {
	if isWorkflow(p) {
		return true
	}
	name := path.Base(p)
	if wholeNames[name] {
		return true
	}
	for _, re := range wholePatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
