// Package packs holds the wording files, built into the binary. The source
// of truth is packs/ at the repository root; go generate copies it here.
package packs

//go:generate cp ../../../packs/checks/en.yaml data/checks.en.yaml
//go:generate cp ../../../packs/regions.yaml data/regions.yaml
//go:generate cp ../../../packs/countries/names.yaml data/countries/names.yaml
//go:generate cp ../../../packs/countries/ng.yaml data/countries/ng.yaml

import (
	_ "embed"
	"fmt"
	"regexp"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed data/checks.en.yaml
var checksEN []byte

// Pack is the wording for every check in one language.
type Pack struct {
	Version     int               `yaml:"version"`
	Language    string            `yaml:"language"`
	TotalChecks int               `yaml:"total_checks"`
	Skips       map[string]string `yaml:"skips"`
	Checks      []Check           `yaml:"checks"`

	byID map[string]*Check
}

// Check is the wording for one check.
type Check struct {
	ID         string             `yaml:"id"`
	Area       string             `yaml:"area"`
	Name       string             `yaml:"name"`
	Reads      string             `yaml:"reads"`
	Root       Root               `yaml:"root"`
	Passed     string             `yaml:"passed"`
	PassedNone string             `yaml:"passed-none"`
	Skips      map[string]string  `yaml:"skips"`
	Findings   map[string]Finding `yaml:"findings"`
}

// Root says whether a check needs root, and why.
type Root struct {
	Needed string `yaml:"needed"` // never, sometimes or always
	Why    string `yaml:"why"`
}

// Finding is the wording and severity for one kind of finding.
type Finding struct {
	Severity    string            `yaml:"severity"`
	Confidence  string            `yaml:"confidence"`
	Sentence    string            `yaml:"sentence"`
	Why         string            `yaml:"why"`
	Fix         string            `yaml:"fix"`
	FixVariants map[string]string `yaml:"fix-variants"`
	// Auto names the kiyesi fix that makes this change, when one can.
	Auto string `yaml:"auto"`
}

var (
	loadOnce sync.Once
	english  *Pack
	loadErr  error
)

// English returns the built-in English pack.
func English() (*Pack, error) {
	loadOnce.Do(func() { english, loadErr = Parse(checksEN) })
	return english, loadErr
}

// Parse reads a pack and checks that it is complete.
func Parse(data []byte) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("reading the wording file: %w", err)
	}
	p.byID = make(map[string]*Check, len(p.Checks))
	for i := range p.Checks {
		c := &p.Checks[i]
		if c.ID == "" || c.Name == "" || c.Passed == "" || c.Reads == "" {
			return nil, fmt.Errorf("check %q is missing an id, name, reads or passed line", c.ID)
		}
		if _, dup := p.byID[c.ID]; dup {
			return nil, fmt.Errorf("check %q appears twice", c.ID)
		}
		switch c.Root.Needed {
		case "never":
		case "sometimes", "always":
			if c.Root.Why == "" {
				return nil, fmt.Errorf("check %q needs root but does not say why", c.ID)
			}
		default:
			return nil, fmt.Errorf("check %q: root.needed must be never, sometimes or always", c.ID)
		}
		for key, f := range c.Findings {
			switch f.Severity {
			case "critical", "warning", "info":
			default:
				return nil, fmt.Errorf("check %q finding %q: unknown severity %q", c.ID, key, f.Severity)
			}
			if f.Sentence == "" || f.Why == "" || f.Fix == "" {
				return nil, fmt.Errorf("check %q finding %q needs a sentence, a why and a fix", c.ID, key)
			}
		}
		p.byID[c.ID] = c
	}
	return &p, nil
}

// Check returns the wording for one check, or nil.
func (p *Pack) Check(id string) *Check { return p.byID[id] }

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// Fill replaces each {name} in s with vars[name]. A placeholder with no
// value is left as it is, so a missing value is visible rather than blank.
func Fill(s string, vars map[string]string) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := vars[m[1:len(m)-1]]; ok {
			return v
		}
		return m
	})
}
