package langpkg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// npm's package-lock.json: "packages" (lockfile 2 and 3), or the nested
// "dependencies" of lockfile 1.
func parseNpmLock(b []byte) [][2]string {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out [][2]string
	for k, p := range lock.Packages {
		i := strings.LastIndex(k, "node_modules/")
		if i < 0 || p.Version == "" {
			continue
		}
		name := k[i+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name
		}
		out = append(out, [2]string{name, p.Version})
	}
	var walk func(map[string]json.RawMessage, int)
	walk = func(deps map[string]json.RawMessage, depth int) {
		if depth > 20 {
			return
		}
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) == nil {
				if d.Version != "" && !strings.Contains(d.Version, ":") {
					out = append(out, [2]string{name, d.Version})
				}
				walk(d.Dependencies, depth+1)
			}
		}
	}
	if len(lock.Packages) == 0 {
		walk(lock.Dependencies, 0)
	}
	return out
}

// yarn.lock, classic ("name@range": then `  version "1.2.3"`) and Berry
// ("name@npm:range": then `  version: 1.2.3`).
func parseYarnLock(b []byte) [][2]string {
	var out [][2]string
	name := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			first := strings.TrimSpace(strings.Split(strings.TrimSuffix(line, ":"), ",")[0])
			first = strings.Trim(first, `"`)
			// The name is up to the @ that starts the range; a scope starts with @.
			at := strings.Index(first[min(1, len(first)):], "@")
			if at < 0 {
				name = ""
				continue
			}
			name = first[:at+1]
			continue
		}
		t := strings.TrimSpace(line)
		if name != "" && strings.HasPrefix(t, "version") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "version:"), "version")), `"`)
			out = append(out, [2]string{name, v})
			name = ""
		}
	}
	return out
}

// pnpm-lock.yaml's package keys: /name@1.2.3, name@1.2.3 (lockfile 9), /name/1.2.3 (lockfile 5).
var pnpmKey = regexp.MustCompile(`^\s{2}['"]?/?((?:@[^/@\s]+/)?[^/@\s(]+)[@/]([0-9][^\s('":]*)`)

func parsePnpmLock(b []byte) [][2]string {
	var out [][2]string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			in = strings.HasPrefix(line, "packages:") || strings.HasPrefix(line, "snapshots:")
			continue
		}
		if !in || strings.HasPrefix(line, "    ") {
			continue
		}
		if m := pnpmKey.FindStringSubmatch(line); m != nil {
			out = append(out, [2]string{m[1], m[2]})
		}
	}
	return out
}

// [[package]] tables with name and version: poetry.lock, uv.lock, Cargo.lock.
func parseTOMLPackages(b []byte) [][2]string {
	var out [][2]string
	in := false
	name, version := "", ""
	flush := func() {
		if in && name != "" && version != "" {
			out = append(out, [2]string{name, version})
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			flush()
			in = t == "[[package]]"
			continue
		}
		if !in {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok {
			v = strings.Trim(strings.TrimSpace(v), `"`)
			switch strings.TrimSpace(k) {
			case "name":
				name = v
			case "version":
				version = v
			}
		}
	}
	flush()
	return out
}

// Pipfile.lock: {"default": {"name": {"version": "==1.2.3"}}, "develop": …}.
func parsePipfileLock(b []byte) [][2]string {
	var lock map[string]map[string]struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out [][2]string
	for section, pkgs := range lock {
		if section == "_meta" {
			continue
		}
		for name, p := range pkgs {
			if v := strings.TrimPrefix(p.Version, "=="); v != p.Version {
				out = append(out, [2]string{name, v})
			}
		}
	}
	return out
}

// go.sum: "module version hash"; the go.mod line of a module is skipped.
func parseGoSum(b []byte) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		out = append(out, [2]string{f[0], strings.TrimPrefix(f[1], "v")})
	}
	return out
}

// gradle.lockfile: group:artifact:version=configurations.
func parseGradleLock(b []byte) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(string(b), "\n") {
		coord, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		p := strings.Split(coord, ":")
		if len(p) == 3 && !strings.HasPrefix(coord, "#") {
			out = append(out, [2]string{p[0] + ":" + p[1], p[2]})
		}
	}
	return out
}

// Gemfile.lock: under "  specs:", gems at four spaces: "    name (1.2.3)".
var gemLine = regexp.MustCompile(`^ {4}([A-Za-z0-9_.-]+) \(([0-9][0-9A-Za-z.]*)(?:-[a-z0-9_]+(?:-[a-z0-9_]+)*)?\)$`)

func parseGemfileLock(b []byte) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(string(b), "\n") {
		if m := gemLine.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			out = append(out, [2]string{m[1], m[2]})
		}
	}
	return out
}

// packages.lock.json: {"dependencies": {"net8.0": {"Name": {"resolved": "1.2.3"}}}}.
func parseNuGetLock(b []byte) [][2]string {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
			Type     string `json:"type"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out [][2]string
	for _, fw := range lock.Dependencies {
		for name, d := range fw {
			if d.Resolved != "" && d.Type != "Project" {
				out = append(out, [2]string{name, d.Resolved})
			}
		}
	}
	return out
}

// A published .NET app's <app>.deps.json: {"libraries": {"Name/1.2.3": {"type": "package"}}}.
func parseDepsJSON(b []byte) [][2]string {
	var deps struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if json.Unmarshal(b, &deps) != nil {
		return nil
	}
	var out [][2]string
	for k, l := range deps.Libraries {
		if name, v, ok := strings.Cut(k, "/"); ok && l.Type == "package" {
			out = append(out, [2]string{name, v})
		}
	}
	return out
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func composerList(ps []composerPackage) [][2]string {
	var out [][2]string
	for _, p := range ps {
		out = append(out, [2]string{p.Name, strings.TrimPrefix(p.Version, "v")})
	}
	return out
}

// composer.lock: {"packages": [...], "packages-dev": [...]}.
func parseComposerLock(b []byte) [][2]string {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	return composerList(append(lock.Packages, lock.PackagesDev...))
}

// vendor/composer/installed.json: a list (Composer 1) or {"packages": [...]} (2).
func parseComposerInstalled(b []byte) [][2]string {
	var two struct {
		Packages []composerPackage `json:"packages"`
	}
	if json.Unmarshal(b, &two) == nil && len(two.Packages) > 0 {
		return composerList(two.Packages)
	}
	var one []composerPackage
	if json.Unmarshal(b, &one) == nil {
		return composerList(one)
	}
	return nil
}

// node_modules with no lockfile beside it: each package's own package.json,
// scoped ones one level down, and the packages nested inside them.
func (w *walker) nodeModules(r Root, dir string) {
	var pkgs [][2]string
	var read func(string, int)
	read = func(d string, depth int) {
		if depth > 4 || w.stop() {
			return
		}
		ents, err := fs.ReadDir(w.fsys, d)
		if err != nil {
			return
		}
		w.entries += len(ents)
		for _, e := range ents {
			n := e.Name()
			if !e.IsDir() || strings.HasPrefix(n, ".") {
				continue
			}
			if strings.HasPrefix(n, "@") {
				read(path.Join(d, n), depth)
				continue
			}
			p := path.Join(d, n)
			if b, err := fs.ReadFile(w.fsys, path.Join(p, "package.json")); err == nil && len(b) < 1<<20 {
				var pj struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}
				if json.Unmarshal(b, &pj) == nil && pj.Name != "" {
					pkgs = append(pkgs, [2]string{pj.Name, pj.Version})
				}
			}
			read(path.Join(p, "node_modules"), depth+1)
		}
	}
	read(dir, 0)
	w.add(r, dir, Npm, pkgs)
}

// site-packages: each installed distribution's folder, name-version.dist-info
// or name-version.egg-info.
func (w *walker) sitePackages(r Root, dir string) {
	ents, err := fs.ReadDir(w.fsys, dir)
	if err != nil {
		return
	}
	w.entries += len(ents)
	var pkgs [][2]string
	for _, e := range ents {
		n := e.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(n, ".dist-info"), ".egg-info")
		if base == n {
			continue
		}
		if i := strings.Index(base, "-"); i > 0 {
			v := base[i+1:]
			if j := strings.Index(v, "-py"); j > 0 {
				v = v[:j]
			}
			pkgs = append(pkgs, [2]string{base[:i], v})
		}
	}
	w.add(r, dir, PyPI, pkgs)
}

// Installed gems: specifications/name-1.2.3.gemspec.
var gemSpec = regexp.MustCompile(`^(.+)-([0-9][^-]*)(?:-[a-z0-9_-]+)?\.gemspec$`)

func (w *walker) gemSpecs(r Root, dir string) {
	ents, err := fs.ReadDir(w.fsys, dir)
	if err != nil {
		return
	}
	w.entries += len(ents)
	var pkgs [][2]string
	for _, e := range ents {
		if m := gemSpec.FindStringSubmatch(e.Name()); m != nil {
			pkgs = append(pkgs, [2]string{m[1], m[2]})
		}
	}
	w.add(r, dir, RubyGems, pkgs)
}
