package pullcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

// The git hook and the service read the same files whole: the names in
// api/src/features/pullchecks/files.ts are the names here.
func TestReadWholeMatchesTheService(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "src", "features", "pullchecks", "files.ts"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)const NAMES = new Set\(\[(.*?)\]\);`).FindSubmatch(src)
	if block == nil {
		t.Fatal("files.ts has no NAMES set; did it move?")
	}
	var theirs []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(block[1], -1) {
		theirs = append(theirs, string(m[1]))
	}
	var ours []string
	for n := range wholeNames {
		ours = append(ours, n)
	}
	sort.Strings(theirs)
	sort.Strings(ours)
	if strings.Join(theirs, ",") != strings.Join(ours, ",") {
		t.Errorf("names differ:\n service %v\n engine  %v", theirs, ours)
	}
	pats := regexp.MustCompile(`(?s)const PATTERNS = \[(.*?)\];`).FindSubmatch(src)
	if pats == nil {
		t.Fatal("files.ts has no PATTERNS; did it move?")
	}
	var theirPats []string
	for _, m := range regexp.MustCompile(`/(\^?[^/]+\$)/`).FindAllSubmatch(pats[1], -1) {
		theirPats = append(theirPats, string(m[1]))
	}
	var ourPats []string
	for _, re := range wholePatterns {
		ourPats = append(ourPats, re.String())
	}
	if strings.Join(theirPats, ",") != strings.Join(ourPats, ",") {
		t.Errorf("patterns differ:\n service %v\n engine  %v", theirPats, ourPats)
	}
}

func TestReadWhole(t *testing.T) {
	for p, want := range map[string]bool{
		"package.json": true, "web/yarn.lock": true, "requirements-dev.txt": true, "src/App/App.csproj": true,
		"lib.gemspec": true, ".github/workflows/ci.yml": true, ".github/workflows/sub/ci.yml": false,
		"src/index.js": false, "README.md": false, "docs/.github/workflows/ci.yml": false,
	} {
		if got := ReadWhole(p); got != want {
			t.Errorf("ReadWhole(%q) = %v, want %v", p, got, want)
		}
	}
	// Every dependency file a rule reads is read whole.
	data, err := packs.LoadPullChecks()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range data.Files {
		name := strings.ReplaceAll(f.Name, "*", "x")
		if !ReadWhole("sub/" + name) {
			t.Errorf("%s is a dependency file but is not read whole", f.Name)
		}
	}
}
