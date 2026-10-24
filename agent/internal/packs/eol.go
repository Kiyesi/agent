package packs

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

//go:embed data/eol.yaml
var eolYAML []byte

// Release is one release's end of security fixes.
type Release struct {
	// Fixes is the last day of free security fixes.
	Fixes time.Time
	// Regular is Debian's last day of the security team's own support,
	// before long-term support takes over until Fixes, or zero.
	Regular time.Time
	// Extended is the last day of paid extended fixes (Ubuntu Pro), or zero.
	Extended time.Time
}

// EndOfLife is the table of releases, by system and release.
type EndOfLife struct {
	// Fetched is the day the table was made.
	Fetched string
	systems map[string]map[string]Release
}

var (
	eolOnce  sync.Once
	eolTable *EndOfLife
	eolErr   error
)

// LoadEndOfLife reads the built-in table, once.
func LoadEndOfLife() (*EndOfLife, error) {
	eolOnce.Do(func() { eolTable, eolErr = ParseEndOfLife(eolYAML) })
	return eolTable, eolErr
}

// ParseEndOfLife reads a table in the form of packs/eol.yaml.
func ParseEndOfLife(data []byte) (*EndOfLife, error) {
	var raw struct {
		Fetched string                                  `yaml:"fetched"`
		Systems map[string]map[string]map[string]string `yaml:"systems"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	t := &EndOfLife{Fetched: raw.Fetched, systems: map[string]map[string]Release{}}
	day := func(s string) (time.Time, error) { return time.Parse("2006-01-02", s) }
	for sys, rels := range raw.Systems {
		t.systems[sys] = map[string]Release{}
		for rel, v := range rels {
			fixes, err := day(v["fixes"])
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", sys, rel, err)
			}
			r := Release{Fixes: fixes}
			for k, dst := range map[string]*time.Time{"regular": &r.Regular, "extended": &r.Extended} {
				if v[k] == "" {
					continue
				}
				if *dst, err = day(v[k]); err != nil {
					return nil, fmt.Errorf("%s %s: %w", sys, rel, err)
				}
			}
			t.systems[sys][rel] = r
		}
	}
	return t, nil
}

// Knows says whether the table has dates for a system at all.
func (t *EndOfLife) Knows(system string) bool { return t.systems[system] != nil }

// Lookup finds a system's release, by the same rules as the service's tips:
// Ubuntu, Amazon Linux and Fedora by their whole version, Alpine by major
// and minor, the others by their major version. name is os-release's
// PRETTY_NAME, which tells CentOS Stream from CentOS.
func (t *EndOfLife) Lookup(id, version, name string) (system, release string, r Release, ok bool) {
	system = id
	if id == "centos" && strings.Contains(strings.ToLower(name), "stream") {
		system = "centos-stream"
	}
	parts := strings.Split(version, ".")
	switch system {
	case "ubuntu", "amzn", "fedora":
		release = version
	case "alpine":
		if len(parts) >= 2 {
			release = parts[0] + "." + parts[1]
		}
	default:
		release = parts[0]
	}
	r, ok = t.systems[system][release]
	return system, release, r, ok
}
