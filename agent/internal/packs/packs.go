// Package packs holds the wording files, built into the binary. The source
// of truth is packs/ at the repository root; go generate copies it here.
package packs

//go:generate cp ../../../packs/checks/en.yaml data/checks.en.yaml
//go:generate cp ../../../packs/regions.yaml data/regions.yaml
//go:generate cp ../../../packs/countries/names.yaml data/countries/names.yaml
//go:generate cp ../../../packs/countries/ng.yaml data/countries/ng.yaml
//go:generate cp ../../../packs/eol.yaml data/eol.yaml

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
	ID         string `yaml:"id"`
	Area       string `yaml:"area"`
	Name       string `yaml:"name"`
	Reads      string `yaml:"reads"`
	Root       Root   `yaml:"root"`
	Passed     string `yaml:"passed"`
	PassedNone string `yaml:"passed-none"`
	// PassedNoHome is the passed line when no home country is chosen.
	PassedNoHome string             `yaml:"passed-no-home"`
	Skips        map[string]string  `yaml:"skips"`
	Findings     map[string]Finding `yaml:"findings"`
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

var placeholder = regexp.MustCompile(`\{([a-z_]+)((?:\|[^{}|]*)*)\}`)

// Fill replaces each {name} in s with vars[name]. A placeholder with no
// value is left as it is, so a missing value is visible rather than blank.
//
// A count can carry its words, so they agree with it:
//
//	{count|update has|updates have}           1 update has, 3 updates have
//	{count|no containers|container|containers} no containers, 1 container, 2 containers
//	{days|in}                                  today, tomorrow, in 9 days
//	{days|ago}                                 today, yesterday, 3 days ago
// fillDefaults are the words for a value a finding may not carry, such as
// one saved by an agent from before the value existed.
var fillDefaults = map[string]string{"provider_firewall": "your provider's firewall"}

func Fill(s string, vars map[string]string) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		parts := placeholder.FindStringSubmatch(m)
		v, ok := vars[parts[1]]
		if !ok {
			v, ok = fillDefaults[parts[1]]
		}
		if !ok {
			return m
		}
		if parts[2] == "" {
			return v
		}
		forms := strings.Split(parts[2][1:], "|")
		n, err := strconv.Atoi(v)
		if err != nil {
			return v + " " + forms[len(forms)-1]
		}
		switch {
		case len(forms) == 1 && forms[0] == "in":
			return map[int]string{0: "today", 1: "tomorrow"}[n] + inDays(n, "in %d days")
		case len(forms) == 1 && forms[0] == "ago":
			return map[int]string{0: "today", 1: "yesterday"}[n] + inDays(n, "%d days ago")
		case len(forms) < 2:
			return v
		case len(forms) == 3 && n == 0:
			return forms[0]
		case n == 1:
			return v + " " + forms[len(forms)-2]
		default:
			return v + " " + forms[len(forms)-1]
		}
	})
}

// inDays is the words for more than a day; empty for today or a day away.
func inDays(n int, format string) string {
	if n == 0 || n == 1 {
		return ""
	}
	return fmt.Sprintf(format, n)
}
