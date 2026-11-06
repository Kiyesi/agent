// Package langpkg lists the language packages installed on a server and in
// its running containers, for the service's malicious package check: npm,
// Python, Go, Java (Maven), Ruby, Rust, .NET (NuGet) and PHP (Composer).
// It reads lockfiles and what package managers record when they install,
// read-only, within limits on files, size and time. It runs nothing.
package langpkg

import (
	"context"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// The languages, by their OSV ecosystem names, as the service matches them.
const (
	Npm       = "npm"
	PyPI      = "PyPI"
	Go        = "Go"
	Maven     = "Maven"
	RubyGems  = "RubyGems"
	Crates    = "crates.io"
	NuGet     = "NuGet"
	Packagist = "Packagist"
)

// All is every language read, in the order a scan names them.
var All = []string{Npm, PyPI, Go, Maven, RubyGems, Crates, NuGet, Packagist}

// Limits keep a large server's scan quick and small.
const (
	MaxPackages = 15000
	maxSources  = 500
	maxFile     = 8 << 20 // a big lockfile, never a log
	maxEntries  = 60000   // directory entries looked at, per scan
	maxDepth    = 6
)

// Source is the packages found in one place: a file or folder, and in a
// container, its name before the path.
type Source struct {
	Where     string      `json:"where"`
	Ecosystem string      `json:"ecosystem"`
	Packages  [][2]string `json:"packages"`
}

// Result is what one scan read.
type Result struct {
	Sources []Source
	// Read is every language the reader looked for.
	Read []string
}

// Root is a place to look: the server itself, or a running container's files.
type Root struct {
	// Dir is relative to the file system given, without a leading slash ("" for the server).
	Dir string
	// Container names it in Where; empty for the server itself.
	Container string
}

// Where applications and installed packages usually live, inside a root.
var places = []string{
	"srv", "var/www", "opt", "home", "app", "usr/src/app", "code", "root",
	"usr/lib/node_modules", "usr/local/lib/node_modules",
	"usr/lib/python3", "usr/local/lib/python3", "usr/lib/python3/dist-packages",
	"var/lib/gems", "usr/local/bundle", "usr/lib/ruby/gems",
}

// Folders never worth walking into.
var skip = map[string]bool{
	".git": true, "proc": true, "sys": true, "dev": true, ".cache": true, "tmp": true,
	"__pycache__": true, ".next": true, "dist": true, "build": true, "coverage": true,
}

type walker struct {
	fsys    fs.FS
	ctx     context.Context
	until   time.Time
	entries int
	total   int
	sources []Source
	seen    map[string]bool
}

// Read looks in each root's usual places for what is installed, until the
// limits or the deadline.
func Read(ctx context.Context, fsys fs.FS, roots []Root, budget time.Duration) Result {
	w := &walker{fsys: fsys, ctx: ctx, until: time.Now().Add(budget), seen: map[string]bool{}}
	for _, r := range roots {
		for _, p := range places {
			dir := p
			if r.Dir != "" {
				dir = path.Join(r.Dir, p)
			}
			// Python's folders carry their version in the name: python3.12.
			if strings.HasSuffix(p, "/python3") {
				parent := path.Dir(dir)
				if ents, err := fs.ReadDir(fsys, parent); err == nil {
					for _, e := range ents {
						if e.IsDir() && strings.HasPrefix(e.Name(), "python3") {
							w.walk(r, path.Join(parent, e.Name()), 0)
						}
					}
				}
				continue
			}
			w.walk(r, dir, 0)
		}
	}
	sort.Slice(w.sources, func(i, j int) bool {
		if w.sources[i].Ecosystem != w.sources[j].Ecosystem {
			return w.sources[i].Ecosystem < w.sources[j].Ecosystem
		}
		return w.sources[i].Where < w.sources[j].Where
	})
	return Result{Sources: w.sources, Read: All}
}

func (w *walker) stop() bool {
	return w.entries >= maxEntries || w.total >= MaxPackages || len(w.sources) >= maxSources ||
		time.Now().After(w.until) || w.ctx.Err() != nil
}

func (w *walker) walk(r Root, dir string, depth int) {
	if w.stop() || depth > maxDepth || w.seen[dir] {
		return
	}
	w.seen[dir] = true
	ents, err := fs.ReadDir(w.fsys, dir)
	if err != nil {
		return
	}
	w.entries += len(ents)
	names := map[string]bool{}
	for _, e := range ents {
		names[e.Name()] = true
	}
	// Lockfiles name every package a project installs, so a folder that has
	// one is read from it, and its node_modules is not walked as well.
	locked := false
	for _, f := range lockfiles {
		if names[f.name] {
			w.file(r, path.Join(dir, f.name), f.ecosystem, f.parse)
			if f.ecosystem == Npm {
				locked = true
			}
		}
	}
	for _, e := range ents {
		n := e.Name()
		full := path.Join(dir, n)
		switch {
		case strings.HasSuffix(n, ".deps.json") && !e.IsDir():
			w.file(r, full, NuGet, parseDepsJSON)
		case e.IsDir() && n == "node_modules":
			if !locked {
				w.nodeModules(r, full)
			}
		case e.IsDir() && (n == "site-packages" || n == "dist-packages"):
			w.sitePackages(r, full)
		case e.IsDir() && n == "specifications" && strings.Contains(dir, "gems"):
			w.gemSpecs(r, full)
		case e.IsDir() && !skip[n] && !strings.HasPrefix(n, "."):
			w.walk(r, full, depth+1)
		}
		if w.stop() {
			return
		}
	}
}

type lockfile struct {
	name      string
	ecosystem string
	parse     func([]byte) [][2]string
}

var lockfiles = []lockfile{
	{"package-lock.json", Npm, parseNpmLock},
	{"npm-shrinkwrap.json", Npm, parseNpmLock},
	{"yarn.lock", Npm, parseYarnLock},
	{"pnpm-lock.yaml", Npm, parsePnpmLock},
	{"poetry.lock", PyPI, parseTOMLPackages},
	{"Pipfile.lock", PyPI, parsePipfileLock},
	{"uv.lock", PyPI, parseTOMLPackages},
	{"go.sum", Go, parseGoSum},
	{"gradle.lockfile", Maven, parseGradleLock},
	{"Gemfile.lock", RubyGems, parseGemfileLock},
	{"Cargo.lock", Crates, parseTOMLPackages},
	{"packages.lock.json", NuGet, parseNuGetLock},
	{"composer.lock", Packagist, parseComposerLock},
	{"installed.json", Packagist, parseComposerInstalled},
}

// where says a place the way people read it: /srv/shop/package-lock.json,
// or "container api: /app/package-lock.json".
func (r Root) where(p string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(p, r.Dir), "/")
	if r.Container != "" {
		return "container " + r.Container + ": /" + rel
	}
	return "/" + rel
}

func (w *walker) add(r Root, at, eco string, pkgs [][2]string) {
	if len(pkgs) == 0 || w.stop() {
		return
	}
	pkgs = dedupe(pkgs)
	if room := MaxPackages - w.total; len(pkgs) > room {
		pkgs = pkgs[:room]
	}
	w.total += len(pkgs)
	w.sources = append(w.sources, Source{Where: r.where(at), Ecosystem: eco, Packages: pkgs})
}

func (w *walker) file(r Root, p, eco string, parse func([]byte) [][2]string) {
	// composer's installed.json lives in vendor/composer only.
	if eco == Packagist && path.Base(p) == "installed.json" && !strings.HasSuffix(path.Dir(p), "vendor/composer") {
		return
	}
	info, err := fs.Stat(w.fsys, p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFile {
		return
	}
	b, err := fs.ReadFile(w.fsys, p)
	if err != nil {
		return
	}
	w.add(r, p, eco, parse(b))
}

func dedupe(pkgs [][2]string) [][2]string {
	seen := map[[2]string]bool{}
	out := pkgs[:0]
	for _, p := range pkgs {
		p[0], p[1] = strings.TrimSpace(p[0]), strings.TrimSpace(p[1])
		if p[0] == "" || p[1] == "" || len(p[0]) > 214 || len(p[1]) > 100 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}
