// Package pullcheck checks what a change to a repository adds: a pull
// request on GitHub, or (from week 43) a push checked by the git hook. It
// knows nothing of GitHub: it is given each changed file's text before and
// after, or the lines the change adds, and returns findings. It reads only
// what it is given and the malicious-package list file; it runs nothing,
// opens no network connection and writes no file.
//
// Five rules, each with the files it reads:
//
//   - malicious: packages added or changed in dependency files, matched
//     against the malicious-package list. npm: package.json,
//     package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml.
//     PyPI: requirements*.txt (pinned with ==), poetry.lock, Pipfile.lock,
//     uv.lock. Go: go.mod, go.sum. Maven: pom.xml (explicit versions),
//     gradle.lockfile. RubyGems: Gemfile.lock. crates.io: Cargo.lock.
//     NuGet: packages.lock.json, *.csproj (PackageReference). Packagist:
//     composer.lock.
//   - lockfile: a package downloaded from a host that is not its registry
//     (nor one of the team's), or the same version with a new checksum.
//     package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml,
//     Cargo.lock, composer.lock, go.sum (checksums only), Pipfile.lock,
//     poetry.lock, uv.lock, Gemfile.lock.
//   - install: install scripts that download and run code: package.json
//     and composer.json scripts, setup.py, build.rs, extconf.rb, Gemfile
//     and *.gemspec; and new npm dependencies that run their own install
//     script (package-lock.json hasInstallScript, pnpm-lock.yaml
//     requiresBuild), unless on the known-good list.
//   - hidden: in the lines any text file gains: invisible or
//     direction-reversing characters, and long encoded blocks that are run.
//   - workflow: in .github/workflows/*.yml and *.yaml: actions not pinned
//     to a commit, pull_request_target or workflow_run with a checkout of
//     the pull request's code, and steps that print secrets.
//
// The data the rules use (registries, known-good install scripts, skipped
// folders, the words of each finding) is packs/pullchecks.yaml.
package pullcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

// Limits. The caller stops sooner too; these hold whatever it sends.
const (
	MaxFiles    = 300
	MaxTotal    = 5 << 20
	MaxFile     = 1 << 20
	MaxLine     = 20000
	Deadline    = 20 * time.Second
	maxFindings = 500
	maxPerFile  = 50
)

// The rules, by name.
const (
	RuleMalicious = "malicious"
	RuleLockfile  = "lockfile"
	RuleInstall   = "install"
	RuleHidden    = "hidden"
	RuleWorkflow  = "workflow"
)

// Rules is every rule, in the order they run.
var Rules = []string{RuleMalicious, RuleLockfile, RuleInstall, RuleHidden, RuleWorkflow}

// Input is one change to check.
type Input struct {
	// List is the path of the malicious-package list file.
	List  string   `json:"list"`
	Rules []string `json:"rules"`
	// Registries are the team's own registry hosts.
	Registries []string `json:"registries"`
	// Samples are folders of known samples, skipped.
	Samples []string `json:"samples"`
	// Bot is true for a routine update by a bot: only malicious findings count.
	Bot   bool   `json:"bot"`
	Files []File `json:"files"`
}

// File is one changed file.
type File struct {
	Path     string `json:"path"`
	Previous string `json:"previous"`
	// Status is added, modified, removed or renamed.
	Status string `json:"status"`
	// Patch is the unified diff's hunks, when there is one.
	Patch string `json:"patch"`
	// Before and After are the whole file at each end of the change, for
	// dependency and workflow files; nil otherwise.
	Before *string `json:"before"`
	After  *string `json:"after"`
	Binary bool    `json:"binary"`
}

// Output is what the check found and what it could not read.
type Output struct {
	Findings      []Finding `json:"findings"`
	Languages     []string  `json:"languages"`
	Skipped       []Skipped `json:"skipped"`
	Notes         []string  `json:"notes"`
	ListFetchedAt string    `json:"listFetchedAt,omitempty"`
}

// Finding is one problem in one file.
type Finding struct {
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity"`
	Conclusion  string   `json:"conclusion"`
	Title       string   `json:"title"`
	File        string   `json:"file"`
	Start       int      `json:"start"`
	End         int      `json:"end"`
	Snippet     string   `json:"snippet"`
	How         string   `json:"how"`
	Fix         string   `json:"fix"`
	Fingerprint string   `json:"fingerprint"`
	Package     *Package `json:"package,omitempty"`
	Reports     []string `json:"reports,omitempty"`
}

// Package names a package, by its OSV ecosystem.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// Skipped is a file, or part of one, the check did not read.
type Skipped struct {
	Path string `json:"path"`
	Why  string `json:"why"`
}

// Why a file is skipped, in the contract's words.
const (
	whyOverFile   = "over 1 MB"
	whyBinary     = "binary or compressed"
	whyVendored   = "vendored"
	whyBuilt      = "built"
	whySamples    = "samples folder"
	whyFileLimit  = "over the file limit"
	whySizeLimit  = "over the size limit"
	whyOutOfTime  = "out of time"
	whyLineTooLon = "line too long"
)

var validStatus = map[string]bool{
	"": true, "added": true, "modified": true, "removed": true, "renamed": true,
	"copied": true, "changed": true, "unchanged": true,
}

// Validate says what is wrong with an input, or nil.
func Validate(in Input) error {
	known := map[string]bool{}
	for _, r := range Rules {
		known[r] = true
	}
	for _, r := range in.Rules {
		if !known[r] {
			return fmt.Errorf("unknown rule %q: the rules are %s", r, strings.Join(Rules, ", "))
		}
	}
	for i, f := range in.Files {
		if f.Path == "" {
			return fmt.Errorf("file %d has no path", i+1)
		}
		if !validStatus[f.Status] {
			return fmt.Errorf("file %d has an unknown status %q", i+1, f.Status)
		}
	}
	return nil
}

// checker is one run of Check.
type checker struct {
	ctx        context.Context
	in         Input
	data       *packs.PullChecks
	rules      map[string]bool
	out        Output
	seen       map[string]bool
	languages  map[string]bool
	candidates []candidate
	perFile    map[string]int
}

// Check runs the rules on a change. It never fails: what it cannot read is
// listed in Skipped or Notes.
func Check(ctx context.Context, in Input) Output {
	ctx, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	c := &checker{ctx: ctx, in: in, rules: map[string]bool{}, seen: map[string]bool{}, languages: map[string]bool{}, perFile: map[string]int{}}
	data, err := packs.LoadPullChecks()
	if err != nil {
		c.out.Notes = append(c.out.Notes, "The built-in rules could not be read, so nothing was checked: "+err.Error())
		return c.finish()
	}
	c.data = data
	for _, r := range in.Rules {
		// A bot's routine update alerts only for a malicious package.
		if in.Bot && r != RuleMalicious {
			continue
		}
		c.rules[r] = true
	}
	total := 0
	for i, f := range in.Files {
		p := displayPath(f.Path)
		if i >= MaxFiles {
			c.skip(p, whyFileLimit)
			continue
		}
		if c.ctx.Err() != nil {
			c.skip(p, whyOutOfTime)
			continue
		}
		if why := c.skipWhy(f.Path); why != "" {
			c.skip(p, why)
			continue
		}
		before, after := deref(f.Before), deref(f.After)
		if len(before) > MaxFile || len(after) > MaxFile || len(f.Patch) > MaxFile {
			c.skip(p, whyOverFile)
			continue
		}
		size := len(before) + len(after) + len(f.Patch)
		if total+size > MaxTotal {
			c.skip(p, whySizeLimit)
			continue
		}
		total += size
		if f.Binary || looksBinary(before) || looksBinary(after) || looksBinary(f.Patch) {
			c.skip(p, whyBinary)
			continue
		}
		c.file(f, p)
	}
	if c.rules[RuleMalicious] {
		c.matchList()
	}
	return c.finish()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (c *checker) skip(p, why string) {
	c.out.Skipped = append(c.out.Skipped, Skipped{Path: p, Why: why})
}

func (c *checker) note(s string) {
	for _, n := range c.out.Notes {
		if n == s {
			return
		}
	}
	c.out.Notes = append(c.out.Notes, s)
}

// skipWhy says why a path is not read: vendored, built, or a samples folder.
func (c *checker) skipWhy(p string) string {
	clean := strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
	for _, s := range c.in.Samples {
		s = strings.Trim(strings.TrimPrefix(strings.TrimSpace(s), "./"), "/")
		if s != "" && (clean == s || strings.HasPrefix(clean, s+"/")) {
			return whySamples
		}
	}
	segs := strings.Split(clean, "/")
	// A workflow is never someone else's code.
	if !isWorkflow(clean) {
		for _, seg := range segs[:len(segs)-1] {
			for _, v := range c.data.Vendored {
				if seg == v {
					return whyVendored
				}
			}
			for _, b := range c.data.Built {
				if seg == b {
					return whyBuilt
				}
			}
		}
	}
	base := strings.ToLower(path.Base(clean))
	for _, s := range c.data.BuiltSuffixes {
		if strings.HasSuffix(base, s) {
			return whyBuilt
		}
	}
	return ""
}

// file runs every rule that reads this file.
func (c *checker) file(f File, p string) {
	t := newText(f)
	if t.cut {
		c.skip(p, whyLineTooLon)
	}
	dep, isDep := c.data.DependencyFile(f.Path)
	if isDep && f.After != nil && c.rules[RuleMalicious] {
		c.languages[dep.Ecosystem] = true
		c.malicious(f, p, t, dep)
	}
	if c.ctx.Err() != nil {
		return
	}
	if c.rules[RuleLockfile] && f.After != nil {
		c.lockfile(f, p, t)
	}
	if c.ctx.Err() != nil {
		return
	}
	if c.rules[RuleInstall] {
		c.install(f, p, t)
	}
	if c.ctx.Err() != nil {
		return
	}
	if c.rules[RuleHidden] {
		c.hidden(p, t)
	}
	if c.ctx.Err() != nil {
		return
	}
	if c.rules[RuleWorkflow] && isWorkflow(f.Path) && f.After != nil {
		c.languages["GitHub Actions"] = true
		c.workflow(f, p, t)
	}
}

func isWorkflow(p string) bool {
	p = strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
	dir, base := path.Split(p)
	ext := strings.ToLower(path.Ext(base))
	return dir == ".github/workflows/" && (ext == ".yml" || ext == ".yaml")
}

var severity = map[string][2]string{
	RuleMalicious: {"critical", "failure"},
	RuleHidden:    {"critical", "failure"},
	RuleLockfile:  {"critical", "failure"},
	RuleInstall:   {"warning", "neutral"},
	RuleWorkflow:  {"warning", "neutral"},
}

// words fills one kind of finding's title, how and fix.
func (c *checker) words(kind string, vars map[string]string) (title, how, fix string) {
	w := c.data.Words[kind]
	return packs.Fill(w.Title, vars), packs.Fill(w.How, vars), packs.Fill(w.Fix, vars)
}

// add keeps a finding, once per problem per file.
func (c *checker) add(f Finding) {
	key := f.File + "\x00" + f.Fingerprint
	if c.seen[key] {
		return
	}
	if len(c.out.Findings) >= maxFindings {
		c.note(fmt.Sprintf("Only the first %d findings are listed.", maxFindings))
		return
	}
	if c.perFile[f.File] >= maxPerFile {
		c.note(fmt.Sprintf("Only the first %d findings in %s are listed.", maxPerFile, f.File))
		return
	}
	c.seen[key] = true
	c.perFile[f.File]++
	s := severity[f.Rule]
	f.Severity, f.Conclusion = s[0], s[1]
	c.out.Findings = append(c.out.Findings, f)
}

// fingerprint is the sha256 of its parts.
func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func (c *checker) finish() Output {
	o := c.out
	for _, eco := range []string{"npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "NuGet", "Packagist", "GitHub Actions"} {
		if c.languages[eco] {
			o.Languages = append(o.Languages, eco)
		}
	}
	order := map[string]int{}
	for i, f := range c.in.Files {
		if _, ok := order[displayPath(f.Path)]; !ok {
			order[displayPath(f.Path)] = i
		}
	}
	sort.SliceStable(o.Findings, func(i, j int) bool {
		a, b := o.Findings[i], o.Findings[j]
		if order[a.File] != order[b.File] {
			return order[a.File] < order[b.File]
		}
		return a.Start < b.Start
	})
	if o.Findings == nil {
		o.Findings = []Finding{}
	}
	if o.Languages == nil {
		o.Languages = []string{}
	}
	if o.Skipped == nil {
		o.Skipped = []Skipped{}
	}
	if o.Notes == nil {
		o.Notes = []string{}
	}
	return o
}
