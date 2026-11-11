package pullcheck

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/langpkg"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

// depPkg is one package a dependency file asks for.
type depPkg struct {
	name, version string
	// exact is false for a range, such as ^1.2.0: then base is its lowest
	// version, and a report matches when it covers every version or base.
	exact bool
	base  string
}

// candidate is a package the change adds, waiting to be matched.
type candidate struct {
	eco  string
	pkg  depPkg
	file string
	t    *text
	dep  packs.DependencyFile
}

// malicious notes each package the change adds; matchList matches them
// all against the list at the end, in one read of it.
func (c *checker) malicious(f File, p string, t *text, dep packs.DependencyFile) {
	after, ok := depPackages(f.Path, *f.After)
	if !ok {
		c.note(fmt.Sprintf("%s could not be read, so its packages were not checked.", p))
		return
	}
	old := map[string]bool{}
	if f.Before != nil {
		before, _ := depPackages(f.Path, *f.Before)
		for _, b := range before {
			old[NameKey(dep.Ecosystem, b.name)+"\x00"+b.version] = true
		}
	}
	for _, a := range after {
		if old[NameKey(dep.Ecosystem, a.name)+"\x00"+a.version] {
			continue
		}
		c.candidates = append(c.candidates, candidate{eco: dep.Ecosystem, pkg: a, file: p, t: t, dep: dep})
	}
}

var (
	exactVersion = regexp.MustCompile(`^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.+-]+)?$`)
	lowVersion   = regexp.MustCompile(`\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?`)
)

// spec reads a version as a manifest writes it: one version, or a range.
func spec(name, v string) depPkg {
	v = strings.TrimSpace(v)
	if exactVersion.MatchString(v) {
		return depPkg{name: name, version: strings.TrimPrefix(v, "v"), exact: true}
	}
	d := depPkg{name: name, version: v}
	// A URL, a path or a git source names no version of the registry's.
	if !strings.ContainsAny(v, ":/") {
		d.base = lowVersion.FindString(v)
	}
	return d
}

// depPackages reads the packages a dependency file names.
func depPackages(p, s string) ([]depPkg, bool) {
	base := path.Base(p)
	if looksJSON(s) && jsonTooDeep(s, 256) {
		return nil, false
	}
	if _, pkgs, ok := langpkg.ParseLockfile(base, []byte(s)); ok {
		out := make([]depPkg, 0, len(pkgs))
		for _, pk := range pkgs {
			out = append(out, depPkg{name: pk[0], version: pk[1], exact: true})
		}
		return out, true
	}
	if ok, _ := path.Match("requirements*.txt", base); ok {
		return requirements(s), true
	}
	switch {
	case base == "package.json":
		return packageJSON(s)
	case base == "go.mod":
		return goMod(s), true
	case base == "pom.xml":
		return pomXML(s), true
	case strings.HasSuffix(base, ".csproj"):
		return csproj(s), true
	}
	return nil, true
}

// looksJSON says a text starts as JSON does.
func looksJSON(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

// locatePackage finds a package where a lockfile pins it:
// package-lock.json names it by its folder first, so the root's own list
// of dependencies is not taken for it.
func (t *text) locatePackage(file, name, version string) (int, int) {
	switch path.Base(file) {
	case "package-lock.json", "npm-shrinkwrap.json":
		if start, end := t.locate("node_modules/"+name, version); start > 0 {
			return start, end
		}
	}
	return t.locate(name, version)
}

// package.json: the four kinds of dependencies; npm:name@range aliases
// are read as the package they install.
func packageJSON(s string) ([]depPkg, bool) {
	var pj map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &pj) != nil {
		return nil, false
	}
	var out []depPkg
	for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var deps map[string]string
		if json.Unmarshal(pj[k], &deps) != nil {
			continue
		}
		for name, v := range deps {
			if rest, ok := strings.CutPrefix(v, "npm:"); ok {
				if at := strings.LastIndex(rest, "@"); at > 0 {
					name, v = rest[:at], rest[at+1:]
				}
			}
			out = append(out, spec(name, v))
		}
	}
	return out, true
}

var requirementLine = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,\\]+)`)

// requirements*.txt: only pinned packages (name==1.2.3) say a version.
func requirements(s string) []depPkg {
	var out []depPkg
	for _, l := range strings.Split(s, "\n") {
		if m := requirementLine.FindStringSubmatch(l); m != nil {
			out = append(out, depPkg{name: m[1], version: m[2], exact: true})
		}
	}
	return out
}

// go.mod: require lines, alone or in a block.
func goMod(s string) []depPkg {
	var out []depPkg
	block := false
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		t := strings.TrimSpace(l)
		switch {
		case t == "require (":
			block = true
			continue
		case block && t == ")":
			block = false
			continue
		case strings.HasPrefix(t, "require "):
			t = strings.TrimSpace(strings.TrimPrefix(t, "require "))
		case !block:
			continue
		}
		if f := strings.Fields(t); len(f) >= 2 && strings.HasPrefix(f[1], "v") {
			out = append(out, depPkg{name: f[0], version: strings.TrimPrefix(f[1], "v"), exact: true})
		}
	}
	return out
}

var (
	pomDependency = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	pomGroup      = regexp.MustCompile(`<groupId>\s*([^<]+?)\s*</groupId>`)
	pomArtifact   = regexp.MustCompile(`<artifactId>\s*([^<]+?)\s*</artifactId>`)
	pomVersion    = regexp.MustCompile(`<version>\s*([^<]+?)\s*</version>`)
)

// pom.xml: dependencies with a version written out, not a ${property}.
func pomXML(s string) []depPkg {
	var out []depPkg
	for _, m := range pomDependency.FindAllStringSubmatch(s, 5000) {
		g, a, v := pomGroup.FindStringSubmatch(m[1]), pomArtifact.FindStringSubmatch(m[1]), pomVersion.FindStringSubmatch(m[1])
		if g == nil || a == nil || v == nil || strings.Contains(v[1], "${") {
			continue
		}
		d := spec(g[1]+":"+a[1], strings.Trim(v[1], "[]"))
		out = append(out, d)
	}
	return out
}

var (
	packageReference = regexp.MustCompile(`(?is)<PackageReference\b([^>]*?)(/?)>`)
	referenceName    = regexp.MustCompile(`(?i)\b(?:Include|Update)\s*=\s*"([^"]*)"`)
	referenceVersion = regexp.MustCompile(`(?i)\bVersion\s*=\s*"([^"]*)"`)
	versionElement   = regexp.MustCompile(`(?is)^\s*<Version>\s*([^<]*?)\s*</Version>`)
)

// *.csproj: PackageReference, its version as an attribute or an element.
func csproj(s string) []depPkg {
	var out []depPkg
	for _, m := range packageReference.FindAllStringSubmatchIndex(s, 5000) {
		attrs := s[m[2]:m[3]]
		name := referenceName.FindStringSubmatch(attrs)
		if name == nil {
			continue
		}
		v := ""
		if vm := referenceVersion.FindStringSubmatch(attrs); vm != nil {
			v = vm[1]
		} else if m[4] == m[5] {
			if vm := versionElement.FindStringSubmatch(s[m[1]:min(len(s), m[1]+500)]); vm != nil {
				v = vm[1]
			}
		}
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !strings.Contains(v, ",") {
			v = strings.Trim(v, "[]")
		}
		out = append(out, spec(name[1], v))
	}
	return out
}

var errNoList = errors.New("no list")

// listHead is the list file's first line.
type listHead struct {
	Sha       string `json:"sha"`
	FetchedAt string `json:"fetchedAt"`
}

var listLine = regexp.MustCompile(`^\["(MAL-\d{4}-\d+)","([^"]+)",("(?:[^"\\]|\\.)*")`)

// matchList reads the list once and turns each candidate it covers into a finding.
func (c *checker) matchList() {
	want := map[string]bool{}
	for _, cd := range c.candidates {
		want[cd.eco+"\x00"+NameKey(cd.eco, cd.pkg.name)] = true
	}
	head, entries, err := readList(c.ctx, c.in.List, want)
	if errors.Is(err, errNoList) {
		c.note("The malicious-package list is missing, so no package was checked against it.")
		return
	}
	if err != nil {
		c.note("The malicious-package list could not be read, so no package was checked against it.")
		return
	}
	if head.FetchedAt == "" {
		c.note("The malicious-package list is empty, so no package was checked against it.")
		return
	}
	if at, err := time.Parse(time.RFC3339Nano, head.FetchedAt); err == nil {
		c.out.ListFetchedAt = at.UTC().Format(time.RFC3339)
		c.note("The malicious-package list is from " + at.UTC().Format("2006-01-02 15:04") + " UTC.")
	}
	if c.ctx.Err() != nil {
		c.note("The malicious-package list could not be read in time, so some packages may not have been checked.")
	}
	for _, cd := range c.candidates {
		var reports []string
		for _, e := range entries[cd.eco+"\x00"+NameKey(cd.eco, cd.pkg.name)] {
			hit := false
			if cd.pkg.exact {
				hit = Covers(e, cd.pkg.version)
			} else {
				hit = e.All || (cd.pkg.base != "" && Covers(e, cd.pkg.base))
			}
			if hit {
				reports = append(reports, e.ID)
			}
		}
		if len(reports) == 0 {
			continue
		}
		c.maliciousFinding(cd, unique(reports))
	}
}

func unique(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func (c *checker) maliciousFinding(cd candidate, reports []string) {
	needle := cd.pkg.name
	if cd.eco == "Maven" && path.Base(cd.file) == "pom.xml" {
		_, needle, _ = strings.Cut(needle, ":")
	}
	start, end := cd.t.locatePackage(cd.file, needle, cd.pkg.version)
	files := cd.file
	if cd.dep.Manifest != "" && cd.dep.Manifest != path.Base(cd.file) {
		files = cd.dep.Manifest + " and " + cd.file
	}
	vars := map[string]string{
		"name": cd.pkg.name, "version": cd.pkg.version, "file": cd.file, "files": files,
		"command": strings.ReplaceAll(cd.dep.Command, "<file>", cd.file), "reports": strings.Join(reports, ", "),
	}
	title, how, fix := c.words("malicious", vars)
	c.add(Finding{
		Rule: RuleMalicious, Title: title, File: cd.file, Start: start, End: end,
		Snippet: cd.t.snippet(start, end), How: how, Fix: fix,
		Fingerprint: fingerprint(cd.eco, NameKey(cd.eco, cd.pkg.name), cd.pkg.version),
		Package:     &Package{Ecosystem: cd.eco, Name: cd.pkg.name, Version: cd.pkg.version},
		Reports:     reports,
	})
}

// readList reads the list file's head, and the entries of the packages
// wanted (by ecosystem and name key). Lines are parsed only for those.
func readList(ctx context.Context, file string, want map[string]bool) (listHead, map[string][]Entry, error) {
	var head listHead
	out := map[string][]Entry{}
	if file == "" {
		return head, out, errNoList
	}
	fh, err := os.Open(file) // #nosec G304 -- the list file the caller names; only read
	if errors.Is(err, os.ErrNotExist) {
		return head, out, errNoList
	}
	if err != nil {
		return head, out, err
	}
	defer fh.Close()
	r := bufio.NewReaderSize(fh, 1<<16)
	first := true
	for n := 0; ; n++ {
		l, err := r.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if first {
			first = false
			if l != "" && json.Unmarshal([]byte(l), &head) != nil {
				return head, out, fmt.Errorf("the list's first line is not its head")
			}
			if len(want) == 0 {
				return head, out, nil
			}
		} else if l != "" {
			if e, key, ok := listEntry(l, want); ok {
				out[key] = append(out[key], e)
			}
		}
		if err == io.EOF {
			return head, out, nil
		}
		if err != nil {
			return head, out, err
		}
		if n%4096 == 0 && ctx.Err() != nil {
			return head, out, nil
		}
	}
}

// listEntry reads one line of the list when its package is wanted.
func listEntry(l string, want map[string]bool) (Entry, string, bool) {
	m := listLine.FindStringSubmatch(l[:min(len(l), 2048)])
	if m == nil {
		return Entry{}, "", false
	}
	var name string
	if json.Unmarshal([]byte(m[3]), &name) != nil {
		return Entry{}, "", false
	}
	key := m[2] + "\x00" + NameKey(m[2], name)
	if !want[key] {
		return Entry{}, "", false
	}
	var raw []json.RawMessage
	if json.Unmarshal([]byte(l), &raw) != nil || len(raw) < 6 {
		return Entry{}, "", false
	}
	var e Entry
	var all int
	if json.Unmarshal(raw[0], &e.ID) != nil || json.Unmarshal(raw[1], &e.Eco) != nil || json.Unmarshal(raw[2], &e.Name) != nil ||
		json.Unmarshal(raw[3], &all) != nil || json.Unmarshal(raw[4], &e.Versions) != nil || json.Unmarshal(raw[5], &e.Ranges) != nil {
		return Entry{}, "", false
	}
	e.All = all == 1
	return e, key, true
}
