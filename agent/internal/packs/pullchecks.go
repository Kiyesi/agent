package packs

import (
	_ "embed"
	"fmt"
	"path"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed data/pullchecks.yaml
var pullChecksYAML []byte

// PullChecks is the pull-request checks' data (packs/pullchecks.yaml).
type PullChecks struct {
	Version int    `yaml:"version"`
	Updated string `yaml:"updated"`
	// Registries are the hosts each language's packages come from, by OSV
	// ecosystem name. An entry may carry a path prefix.
	Registries map[string][]string `yaml:"registries"`
	Files      []DependencyFile    `yaml:"files"`
	// KnownGood are npm packages whose install script is fine; name/* is a scope.
	KnownGood     []string           `yaml:"known-good-install-scripts"`
	Bots          []string           `yaml:"bots"`
	Vendored      []string           `yaml:"vendored"`
	Built         []string           `yaml:"built"`
	BuiltSuffixes []string           `yaml:"built-suffixes"`
	GitHubOwners  []string           `yaml:"github-owners"`
	Words         map[string]Wording `yaml:"words"`
}

// DependencyFile is one kind of manifest or lockfile, by its name.
type DependencyFile struct {
	Name      string `yaml:"name"`
	Ecosystem string `yaml:"ecosystem"`
	Manifest  string `yaml:"manifest"`
	Command   string `yaml:"command"`
}

// Wording is the words of one kind of finding.
type Wording struct {
	Title string `yaml:"title"`
	How   string `yaml:"how"`
	Fix   string `yaml:"fix"`
}

// pullCheckWords are the kinds of finding the checks need words for.
var pullCheckWords = []string{
	"malicious", "lockfile-host", "lockfile-source", "lockfile-checksum",
	"install-script", "install-dependency", "install-build",
	"hidden-invisible", "hidden-encoded",
	"workflow-unpinned", "workflow-untrusted", "workflow-secret",
}

var (
	pullOnce sync.Once
	pullData *PullChecks
	pullErr  error
)

// LoadPullChecks reads the built-in data, once.
func LoadPullChecks() (*PullChecks, error) {
	pullOnce.Do(func() { pullData, pullErr = ParsePullChecks(pullChecksYAML) })
	return pullData, pullErr
}

// ParsePullChecks reads data in the form of packs/pullchecks.yaml and checks
// that nothing the checks need is missing.
func ParsePullChecks(data []byte) (*PullChecks, error) {
	var p PullChecks
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("reading the pull-request checks file: %w", err)
	}
	for _, eco := range []string{"npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "NuGet", "Packagist"} {
		if len(p.Registries[eco]) == 0 {
			return nil, fmt.Errorf("the pull-request checks file names no registry for %s", eco)
		}
	}
	for _, f := range p.Files {
		if f.Name == "" || f.Ecosystem == "" || f.Command == "" {
			return nil, fmt.Errorf("dependency file %q needs a name, an ecosystem and a command", f.Name)
		}
		if _, err := path.Match(f.Name, ""); err != nil {
			return nil, fmt.Errorf("dependency file %q: %w", f.Name, err)
		}
	}
	for _, k := range pullCheckWords {
		w := p.Words[k]
		if w.Title == "" || w.How == "" || w.Fix == "" {
			return nil, fmt.Errorf("the pull-request checks file needs a title, how and fix for %s", k)
		}
	}
	if len(p.Bots) == 0 || len(p.Vendored) == 0 || len(p.Built) == 0 || len(p.KnownGood) == 0 {
		return nil, fmt.Errorf("the pull-request checks file needs bots, vendored and built folders, and known-good install scripts")
	}
	return &p, nil
}

// DependencyFile finds what kind of dependency file a path is, by its name.
func (p *PullChecks) DependencyFile(name string) (DependencyFile, bool) {
	base := path.Base(name)
	for _, f := range p.Files {
		if ok, _ := path.Match(f.Name, base); ok {
			return f, true
		}
	}
	return DependencyFile{}, false
}

// IsKnownGood says whether an npm package's install script is on the known-good list.
func (p *PullChecks) IsKnownGood(name string) bool {
	n := strings.ToLower(name)
	for _, k := range p.KnownGood {
		k = strings.ToLower(k)
		if n == k || (strings.HasSuffix(k, "/*") && strings.HasPrefix(n, strings.TrimSuffix(k, "*"))) {
			return true
		}
	}
	return false
}
