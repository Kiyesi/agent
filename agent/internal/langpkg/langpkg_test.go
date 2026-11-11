package langpkg

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func find(r Result, eco, where string) [][2]string {
	for _, s := range r.Sources {
		if s.Ecosystem == eco && s.Where == where {
			return s.Packages
		}
	}
	return nil
}

func TestEveryLanguageOnTheServerAndInAContainer(t *testing.T) {
	merged := "var/lib/docker/overlay2/abc/merged"
	fsys := fstest.MapFS{
		// npm: lockfile 3, and its node_modules not walked a second time.
		"srv/shop/package-lock.json":                    file(`{"lockfileVersion":3,"packages":{"":{"name":"shop"},"node_modules/evil-pkg":{"version":"1.0.0"},"node_modules/@scope/lib":{"version":"2.1.0"},"node_modules/a/node_modules/b":{"version":"0.1.0"}}}`),
		"srv/shop/node_modules/never-read/package.json": file(`{"name":"never-read","version":"9.9.9"}`),
		// yarn classic and Berry, pnpm 9.
		"srv/web/yarn.lock":     file("# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.24.0\"\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n"),
		"srv/berry/yarn.lock":   file("__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n"),
		"srv/pn/pnpm-lock.yaml": file("lockfileVersion: '9.0'\n\npackages:\n\n  '@types/node@20.11.0':\n    resolution: {integrity: x}\n\n  chalk@5.3.0:\n    resolution: {integrity: y}\n"),
		// Python: poetry, Pipfile.lock, and what pip installed.
		"opt/api/poetry.lock":  file("[[package]]\nname = \"Bad_Lib\"\nversion = \"2.0\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\n"),
		"opt/api/Pipfile.lock": file(`{"_meta":{},"default":{"flask":{"version":"==3.0.0"}},"develop":{}}`),
		"usr/local/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA":  file("x"),
		"usr/local/lib/python3.12/site-packages/six-1.16.0-py3.12.egg-info/PKG-INFO": file("x"),
		// Go, Java, Ruby, Rust, .NET, PHP.
		"srv/svc/go.sum":                                       file("github.com/evil/mod v1.2.3 h1:abc=\ngithub.com/evil/mod v1.2.3/go.mod h1:def=\n"),
		"srv/jvm/gradle.lockfile":                              file("# comment\norg.apache:commons-text:1.10.0=runtimeClasspath\nempty=\n"),
		"var/www/rails/Gemfile.lock":                           file("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      actionpack (= 7.1.0)\n    nokogiri (1.16.0-x86_64-linux)\n\nPLATFORMS\n"),
		"srv/rust/Cargo.lock":                                  file("version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"),
		"srv/dotnet/packages.lock.json":                        file(`{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3"},"MyLib":{"type":"Project"}}}}`),
		"srv/dotnet/out/App.deps.json":                         file(`{"libraries":{"Serilog/3.1.1":{"type":"package"},"App/1.0.0":{"type":"project"}}}`),
		"var/www/html/composer.lock":                           file(`{"packages":[{"name":"guzzlehttp/guzzle","version":"7.8.1"}],"packages-dev":[{"name":"phpunit/phpunit","version":"v10.5.0"}]}`),
		"var/www/html/vendor/composer/installed.json":          file(`{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}`),
		"var/lib/gems/3.0.0/specifications/rack-3.0.9.gemspec": file("x"),
		// A container's own files: its app without a lockfile, so node_modules is read.
		merged + "/app/node_modules/express/package.json":                 file(`{"name":"express","version":"4.18.2"}`),
		merged + "/app/node_modules/@acme/x/package.json":                 file(`{"name":"@acme/x","version":"1.0.0"}`),
		merged + "/app/node_modules/express/node_modules/qs/package.json": file(`{"name":"qs","version":"6.11.0"}`),
	}
	r := Read(context.Background(), fsys, []Root{{}, {Dir: merged, Container: "api"}}, time.Minute)
	if !reflect.DeepEqual(r.Read, All) {
		t.Errorf("read = %v", r.Read)
	}
	for _, c := range []struct {
		eco, where string
		want       [][2]string
	}{
		{Npm, "/srv/shop/package-lock.json", [][2]string{{"@scope/lib", "2.1.0"}, {"b", "0.1.0"}, {"evil-pkg", "1.0.0"}}},
		{Npm, "/srv/web/yarn.lock", [][2]string{{"@babel/core", "7.24.0"}, {"left-pad", "1.3.0"}}},
		{Npm, "/srv/berry/yarn.lock", [][2]string{{"lodash", "4.17.21"}}},
		{Npm, "/srv/pn/pnpm-lock.yaml", [][2]string{{"@types/node", "20.11.0"}, {"chalk", "5.3.0"}}},
		{PyPI, "/opt/api/poetry.lock", [][2]string{{"Bad_Lib", "2.0"}, {"requests", "2.31.0"}}},
		{PyPI, "/opt/api/Pipfile.lock", [][2]string{{"flask", "3.0.0"}}},
		{PyPI, "/usr/local/lib/python3.12/site-packages", [][2]string{{"requests", "2.31.0"}, {"six", "1.16.0"}}},
		{Go, "/srv/svc/go.sum", [][2]string{{"github.com/evil/mod", "1.2.3"}}},
		{Maven, "/srv/jvm/gradle.lockfile", [][2]string{{"org.apache:commons-text", "1.10.0"}}},
		{RubyGems, "/var/www/rails/Gemfile.lock", [][2]string{{"nokogiri", "1.16.0"}, {"rails", "7.1.0"}}},
		{RubyGems, "/var/lib/gems/3.0.0/specifications", [][2]string{{"rack", "3.0.9"}}},
		{Crates, "/srv/rust/Cargo.lock", [][2]string{{"serde", "1.0.197"}}},
		{NuGet, "/srv/dotnet/packages.lock.json", [][2]string{{"Newtonsoft.Json", "13.0.3"}}},
		{NuGet, "/srv/dotnet/out/App.deps.json", [][2]string{{"Serilog", "3.1.1"}}},
		{Packagist, "/var/www/html/composer.lock", [][2]string{{"guzzlehttp/guzzle", "7.8.1"}, {"phpunit/phpunit", "10.5.0"}}},
		{Packagist, "/var/www/html/vendor/composer/installed.json", [][2]string{{"monolog/monolog", "3.5.0"}}},
		{Npm, "container api: /app/node_modules", [][2]string{{"@acme/x", "1.0.0"}, {"express", "4.18.2"}, {"qs", "6.11.0"}}},
	} {
		if got := find(r, c.eco, c.where); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s = %v, want %v", c.eco, c.where, got, c.want)
		}
	}
	for _, s := range r.Sources {
		for _, p := range s.Packages {
			if p[0] == "never-read" {
				t.Errorf("node_modules beside a lockfile was read as well: %s", s.Where)
			}
		}
	}
}

func TestLimitsKeepAScanSmall(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion":3,"packages":{`)
	for i := 0; i < MaxPackages+500; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"node_modules/p%d":{"version":"1.0.%d"}`, i, i)
	}
	b.WriteString("}}")
	fsys := fstest.MapFS{
		"srv/big/package-lock.json":   file(b.String()),
		"srv/other/package-lock.json": file(`{"packages":{"node_modules/x":{"version":"1.0.0"}}}`),
		// Too big to be a lockfile: never read.
		"srv/huge/package-lock.json": &fstest.MapFile{Data: make([]byte, maxFile+1)},
	}
	r := Read(context.Background(), fsys, []Root{{}}, time.Minute)
	total := 0
	for _, s := range r.Sources {
		total += len(s.Packages)
	}
	if total != MaxPackages {
		t.Errorf("total = %d, want the cap %d", total, MaxPackages)
	}
	// A spent deadline reads nothing more, and still says what it looked for.
	r = Read(context.Background(), fsys, []Root{{}}, -time.Second)
	if len(r.Sources) != 0 || len(r.Read) != 8 {
		t.Errorf("after the deadline: %+v", r)
	}
}

func TestBrokenFilesAreSkipped(t *testing.T) {
	fsys := fstest.MapFS{
		"srv/a/package-lock.json": file("{not json"),
		"srv/a/composer.lock":     file("[]"),
		"srv/a/yarn.lock":         file("garbage without structure"),
		"srv/a/Cargo.lock":        file("[[package]]\nname = \"half\"\n"),
	}
	if r := Read(context.Background(), fsys, []Root{{}}, time.Minute); len(r.Sources) != 0 {
		t.Errorf("sources = %+v", r.Sources)
	}
}

func TestParseLockfileByName(t *testing.T) {
	eco, pkgs, ok := ParseLockfile("web/Cargo.lock", []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"))
	if !ok || eco != Crates || len(pkgs) != 1 || pkgs[0] != [2]string{"serde", "1.0.0"} {
		t.Errorf("Cargo.lock = %s %v %v", eco, pkgs, ok)
	}
	if _, _, ok := ParseLockfile("README.md", nil); ok {
		t.Error("README.md was read as a lockfile")
	}
}
