package pullcheck

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// resolved is one package as a lockfile pins it: where it is downloaded
// from and its checksums.
type resolved struct {
	name, version string
	urls          []string
	sums          []string
	// hashList is true when sums are the hashes of several files (PyPI):
	// a new file for the same version is normal, a changed one is not.
	hashList bool
	// line is the head line that names it, when the reader knows it.
	line int
}

// lockRead is what one lockfile pins: its packages, and the sources a
// whole file installs from (Gemfile.lock's remotes, Pipfile.lock's indexes).
type lockRead struct {
	eco     string
	pkgs    []resolved
	sources []resolved
}

// readLock reads a lockfile the lockfile rule knows. ok is false for any
// other file.
func readLock(p, s string) (lockRead, bool) {
	base := path.Base(p)
	if looksJSON(s) && jsonTooDeep(s, 256) {
		return lockRead{}, false
	}
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		return lockRead{eco: "npm", pkgs: npmLockResolved(s)}, true
	case "yarn.lock":
		return lockRead{eco: "npm", pkgs: yarnResolved(s)}, true
	case "pnpm-lock.yaml":
		return lockRead{eco: "npm", pkgs: pnpmResolved(s)}, true
	case "Cargo.lock":
		return lockRead{eco: "crates.io", pkgs: tomlResolved(s, false)}, true
	case "poetry.lock", "uv.lock":
		return lockRead{eco: "PyPI", pkgs: tomlResolved(s, true)}, true
	case "composer.lock":
		return lockRead{eco: "Packagist", pkgs: composerResolved(s)}, true
	case "go.sum":
		return lockRead{eco: "Go", pkgs: goSumResolved(s)}, true
	case "Pipfile.lock":
		pkgs, sources := pipfileResolved(s)
		return lockRead{eco: "PyPI", pkgs: pkgs, sources: sources}, true
	case "Gemfile.lock":
		pkgs, sources := gemfileResolved(s)
		return lockRead{eco: "RubyGems", pkgs: pkgs, sources: sources}, true
	}
	return lockRead{}, false
}

// npmEntry is one package in package-lock.json.
type npmEntry struct {
	Version          string `json:"version"`
	Resolved         string `json:"resolved"`
	Integrity        string `json:"integrity"`
	Name             string `json:"name"`
	Link             bool   `json:"link"`
	HasInstallScript bool   `json:"hasInstallScript"`
}

// npmLock reads package-lock.json's packages by their folder, and the
// nested dependencies of lockfile version 1 by name.
func npmLock(s string) map[string]npmEntry {
	var lock struct {
		Packages     map[string]npmEntry        `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal([]byte(s), &lock) != nil {
		return nil
	}
	out := map[string]npmEntry{}
	for k, e := range lock.Packages {
		i := strings.LastIndex(k, "node_modules/")
		if i < 0 || e.Link {
			continue
		}
		if e.Name == "" {
			e.Name = k[i+len("node_modules/"):]
		}
		out[k] = e
	}
	var walk func(prefix string, deps map[string]json.RawMessage, depth int)
	walk = func(prefix string, deps map[string]json.RawMessage, depth int) {
		if depth > 20 {
			return
		}
		for name, raw := range deps {
			var d struct {
				npmEntry
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			k := prefix + "node_modules/" + name
			d.Name = name
			out[k] = d.npmEntry
			walk(k+"/", d.Dependencies, depth+1)
		}
	}
	if len(lock.Packages) == 0 {
		walk("", lock.Dependencies, 0)
	}
	return out
}

func npmLockResolved(s string) []resolved {
	var out []resolved
	for _, e := range npmLock(s) {
		if e.Version == "" {
			continue
		}
		r := resolved{name: e.Name, version: e.Version}
		if e.Resolved != "" {
			r.urls = []string{e.Resolved}
		}
		if e.Integrity != "" {
			r.sums = []string{e.Integrity}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name+out[i].version < out[j].name+out[j].version })
	return out
}

// yarnName is the package a yarn.lock block is for: the first of its
// names, up to the @ that starts the range.
func yarnName(header string) string {
	first := strings.TrimSpace(strings.Split(strings.TrimSuffix(header, ":"), ",")[0])
	first = strings.Trim(first, `"`)
	at := strings.Index(first[min(1, len(first)):], "@")
	if at < 0 {
		return ""
	}
	return first[:at+1]
}

// yarn.lock, classic (resolved "url#sha1", integrity) and Berry
// (resolution, checksum).
func yarnResolved(s string) []resolved {
	var out []resolved
	var cur *resolved
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			flush()
			if strings.HasSuffix(l, ":") {
				cur = &resolved{name: yarnName(l), line: i + 1}
			}
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(l)
		key, val, _ := strings.Cut(t, " ")
		key = strings.TrimSuffix(key, ":")
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "version":
			cur.version = val
		case "resolved":
			u, _, _ := strings.Cut(val, "#")
			cur.urls = append(cur.urls, u)
		case "integrity", "checksum":
			cur.sums = append(cur.sums, val)
		case "resolution":
			if i := strings.Index(val, "@http"); i > 0 {
				cur.urls = append(cur.urls, val[i+1:])
			}
		}
	}
	flush()
	return out
}

var (
	pnpmKey       = regexp.MustCompile(`^  ['"]?/?((?:@[^/@\s]+/)?[^/@\s(]+)[@/]([0-9][^\s('":]*)`)
	pnpmIntegrity = regexp.MustCompile(`\bintegrity:\s*([^,}\s]+)`)
	pnpmTarball   = regexp.MustCompile(`\btarball:\s*([^,}\s]+)`)
)

// pnpm-lock.yaml: under packages:, each package's resolution.
func pnpmResolved(s string) []resolved {
	var out []resolved
	var cur *resolved
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
		}
		cur = nil
	}
	in := false
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			flush()
			in = strings.HasPrefix(l, "packages:")
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(l, "   ") {
			flush()
			if m := pnpmKey.FindStringSubmatch(l); m != nil {
				cur = &resolved{name: m[1], version: m[2], line: i + 1}
			}
			continue
		}
		if cur == nil {
			continue
		}
		if m := pnpmIntegrity.FindStringSubmatch(l); m != nil {
			cur.sums = append(cur.sums, strings.Trim(m[1], `'"`))
		}
		if m := pnpmTarball.FindStringSubmatch(l); m != nil {
			cur.urls = append(cur.urls, strings.Trim(m[1], `'"`))
		}
	}
	flush()
	return out
}

var (
	tomlURL  = regexp.MustCompile(`(git\+|sparse\+|registry\+)?(https?://[^"'\s,}\]]+)`)
	tomlHash = regexp.MustCompile(`\b(?:hash|checksum)\s*=\s*"([^"]+)"`)
)

// [[package]] tables: Cargo.lock (source, checksum), poetry.lock
// ([package.source] url, files' hashes) and uv.lock (source, sdist and
// wheels with url and hash). Git sources are skipped: the manifest names
// them, where a reviewer sees them.
func tomlResolved(s string, hashList bool) []resolved {
	var out []resolved
	var cur *resolved
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for i, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && !strings.HasPrefix(t, "[package.") {
			flush()
			if t == "[[package]]" {
				cur = &resolved{hashList: hashList, line: i + 1}
			}
			continue
		}
		if cur == nil || strings.HasPrefix(t, "#") {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok {
			v = strings.Trim(strings.TrimSpace(v), `"`)
			switch strings.TrimSpace(k) {
			case "name":
				if cur.name == "" {
					cur.name = v
				}
			case "version":
				if cur.version == "" {
					cur.version = v
				}
			}
		}
		for _, m := range tomlURL.FindAllStringSubmatch(t, 50) {
			if m[1] != "git+" {
				cur.urls = append(cur.urls, m[2])
			}
		}
		for _, m := range tomlHash.FindAllStringSubmatch(t, 50) {
			cur.sums = append(cur.sums, m[1])
		}
	}
	flush()
	return out
}

// composer.lock: each package's dist url, and its checksum or commit.
// A dev- version follows a branch, so its commit moves: no checksum then.
func composerResolved(s string) []resolved {
	type ref struct {
		URL       string `json:"url"`
		Shasum    string `json:"shasum"`
		Reference string `json:"reference"`
	}
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    ref    `json:"dist"`
		Source  ref    `json:"source"`
	}
	var lock struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if json.Unmarshal([]byte(s), &lock) != nil {
		return nil
	}
	var out []resolved
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		r := resolved{name: p.Name, version: p.Version}
		if p.Dist.URL != "" {
			r.urls = append(r.urls, p.Dist.URL)
		} else if p.Source.URL != "" {
			r.urls = append(r.urls, p.Source.URL)
		}
		dev := strings.HasPrefix(p.Version, "dev-") || strings.HasSuffix(p.Version, "-dev")
		switch {
		case dev:
		case p.Dist.Shasum != "":
			r.sums = []string{p.Dist.Shasum}
		case p.Dist.Reference != "":
			r.sums = []string{p.Dist.Reference}
		case p.Source.Reference != "":
			r.sums = []string{p.Source.Reference}
		}
		out = append(out, r)
	}
	return out
}

// go.sum: each module version's hash, and its go.mod's.
func goSumResolved(s string) []resolved {
	var out []resolved
	for i, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		out = append(out, resolved{name: f[0], version: f[1], sums: []string{f[2]}, line: i + 1})
	}
	return out
}

// Pipfile.lock: its indexes, and each package's hashes.
func pipfileResolved(s string) ([]resolved, []resolved) {
	var lock map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &lock) != nil {
		return nil, nil
	}
	var meta struct {
		Sources []struct {
			URL string `json:"url"`
		} `json:"sources"`
	}
	var sources []resolved
	if json.Unmarshal(lock["_meta"], &meta) == nil {
		for _, src := range meta.Sources {
			sources = append(sources, resolved{urls: []string{src.URL}})
		}
	}
	var out []resolved
	for _, section := range []string{"default", "develop"} {
		var pkgs map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
		}
		if json.Unmarshal(lock[section], &pkgs) != nil {
			continue
		}
		for name, p := range pkgs {
			if v, ok := strings.CutPrefix(p.Version, "=="); ok {
				out = append(out, resolved{name: name, version: v, sums: p.Hashes, hashList: true})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, sources
}

var gemChecksum = regexp.MustCompile(`^  ([A-Za-z0-9_.-]+) \(([^)]+)\)\s+(sha256=[0-9a-f]+)`)

// Gemfile.lock: the remotes of its GEM sections, and the CHECKSUMS
// section Bundler 2.5 and later write.
func gemfileResolved(s string) ([]resolved, []resolved) {
	var pkgs, sources []resolved
	section := ""
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if l != "" && !strings.HasPrefix(l, " ") {
			section = strings.TrimSpace(l)
			continue
		}
		t := strings.TrimSpace(l)
		switch section {
		case "GEM":
			if u, ok := strings.CutPrefix(t, "remote:"); ok {
				sources = append(sources, resolved{urls: []string{strings.TrimSpace(u)}, line: i + 1})
			}
		case "CHECKSUMS":
			if m := gemChecksum.FindStringSubmatch(l); m != nil {
				pkgs = append(pkgs, resolved{name: m[1], version: m[2], sums: []string{m[3]}, line: i + 1})
			}
		}
	}
	return pkgs, sources
}

// allowed says whether a download URL is on its language's registry or
// one of the team's, and names its host.
func (c *checker) allowed(eco, raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		// Not a download from a host: a path, git, or nothing readable.
		return "", true
	}
	host := strings.ToLower(u.Hostname())
	upath := strings.TrimPrefix(u.Path, "/")
	for _, r := range append(append([]string{}, c.data.Registries[eco]...), c.in.Registries...) {
		r = strings.ToLower(strings.TrimSpace(r))
		r = strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://")
		r = strings.TrimSuffix(r, "/")
		h, p, _ := strings.Cut(r, "/")
		match := h == host
		if strings.Contains(h, ":") {
			match = h == strings.ToLower(u.Host)
		}
		if match && (p == "" || upath == p || strings.HasPrefix(upath, p+"/")) {
			return host, true
		}
	}
	return host, false
}

// sumsChanged says a package's checksums changed between two lockfiles.
func sumsChanged(before, after resolved) bool {
	if len(before.sums) == 0 || len(after.sums) == 0 {
		return false
	}
	if after.hashList {
		now := map[string]bool{}
		for _, s := range after.sums {
			now[s] = true
		}
		for _, s := range before.sums {
			if !now[s] {
				return true
			}
		}
		return false
	}
	a, b := append([]string{}, before.sums...), append([]string{}, after.sums...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, " ") != strings.Join(b, " ")
}

// lockfile finds packages from unexpected hosts and changed checksums.
func (c *checker) lockfile(f File, p string, t *text) {
	after, ok := readLock(f.Path, *f.After)
	if !ok {
		return
	}
	c.languages[after.eco] = true
	dep, _ := c.data.DependencyFile(f.Path)
	command := strings.ReplaceAll(dep.Command, "<file>", p)
	old := map[string]resolved{}
	oldURL := map[string]bool{}
	oldSource := map[string]bool{}
	if f.Before != nil {
		before, _ := readLock(f.Path, *f.Before)
		for _, r := range before.pkgs {
			k := r.name + "\x00" + r.version
			if prev, ok := old[k]; ok {
				r.sums = append(prev.sums, r.sums...)
			}
			old[k] = r
			for _, u := range r.urls {
				oldURL[k+"\x00"+u] = true
			}
		}
		for _, s := range before.sources {
			for _, u := range s.urls {
				oldSource[u] = true
			}
		}
	}
	// A package listed twice (go.sum's module and go.mod lines are told
	// apart by their version) is checked once per entry.
	for i, r := range after.pkgs {
		if i%256 == 0 && c.ctx.Err() != nil {
			return
		}
		k := r.name + "\x00" + r.version
		for _, u := range r.urls {
			host, ok := c.allowed(after.eco, u)
			if ok || oldURL[k+"\x00"+u] {
				continue
			}
			start, end := c.lockLines(t, p, r, u)
			vars := map[string]string{"name": r.name, "version": r.version, "file": p, "host": host, "ecosystem": after.eco, "command": command}
			title, how, fix := c.words("lockfile-host", vars)
			c.add(Finding{
				Rule: RuleLockfile, Title: title, File: p, Start: start, End: end, Snippet: t.snippet(start, end),
				How: how, Fix: fix, Fingerprint: fingerprint(RuleLockfile, p, after.eco+"/"+r.name+"@"+r.version, u),
				Package: &Package{Ecosystem: after.eco, Name: r.name, Version: r.version},
			})
			break
		}
		if prev, ok := old[k]; ok && sumsChanged(prev, r) {
			mark := ""
			if len(r.sums) > 0 {
				mark = r.sums[0]
			}
			start, end := c.lockLines(t, p, r, mark)
			vars := map[string]string{"name": r.name, "version": r.version, "file": p, "ecosystem": after.eco, "command": command}
			title, how, fix := c.words("lockfile-checksum", vars)
			c.add(Finding{
				Rule: RuleLockfile, Title: title, File: p, Start: start, End: end, Snippet: t.snippet(start, end),
				How: how, Fix: fix, Fingerprint: fingerprint(RuleLockfile, p, after.eco+"/"+r.name+"@"+r.version, strings.Join(r.sums, " ")),
				Package: &Package{Ecosystem: after.eco, Name: r.name, Version: r.version},
			})
		}
	}
	for _, s := range after.sources {
		for _, u := range s.urls {
			host, ok := c.allowed(after.eco, u)
			if ok || oldSource[u] {
				continue
			}
			start := s.line
			if start == 0 {
				start = t.lineWith(u, 1)
			}
			vars := map[string]string{"file": p, "host": host, "ecosystem": after.eco, "command": command}
			title, how, fix := c.words("lockfile-source", vars)
			c.add(Finding{
				Rule: RuleLockfile, Title: title, File: p, Start: start, End: start, Snippet: t.snippet(start, start),
				How: how, Fix: fix, Fingerprint: fingerprint(RuleLockfile, p, after.eco, u),
			})
		}
	}
}

// lockLines are the lines from a package's name to its URL or checksum.
func (c *checker) lockLines(t *text, p string, r resolved, mark string) (int, int) {
	start := r.line
	if start == 0 {
		start, _ = t.locatePackage(p, r.name, r.version)
	}
	if start == 0 {
		return 0, 0
	}
	end := start
	if n := t.lineWith(mark, start); n > 0 && n-start <= 30 {
		end = n
	}
	return start, end
}
