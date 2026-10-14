package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The docs show kiyesi commands to copy (guide, "the bar every feature
// must clear": the commands on its docs page are run by the pipeline).
// Each one must name a real command with real flags and the right
// number of arguments, so a renamed flag cannot leave the docs wrong.
func TestEveryCommandInTheDocsParses(t *testing.T) {
	root := filepath.Join("..", "..", "..", "site", "src", "content", "docs")
	if _, err := os.Stat(root); err != nil {
		t.Skip("the docs site is not next to the agent")
	}
	fence := regexp.MustCompile("(?s)```(?:sh|bash|shell)\n(.*?)```")
	placeholder := regexp.MustCompile(`<[^>]+>|\[[^\]]+\]`)
	seen := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".mdx") {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- the repository's own docs
		if err != nil {
			return err
		}
		for _, block := range fence.FindAllStringSubmatch(string(data), -1) {
			for _, line := range strings.Split(block[1], "\n") {
				line, _, _ = strings.Cut(line, " #")
				// The kiyesi part of a pipeline or a redirect: what comes after is the shell's.
				line, _, _ = strings.Cut(line, " | ")
				line, _, _ = strings.Cut(line, " > ")
				line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "sudo "))
				if !strings.HasPrefix(line, "kiyesi ") {
					continue
				}
				args := shellWords(placeholder.ReplaceAllString(line, "x"))[1:]
				seen++
				cmd := newRoot(IO{})
				cmd.InitDefaultCompletionCmd()
				found, rest, err := cmd.Find(args)
				// kiyesi alone takes flags only, such as --project.
				if err != nil || (found == cmd && len(args) > 0 && !strings.HasPrefix(args[0], "-")) {
					t.Errorf("%s: %q is not a kiyesi command", path, line)
					continue
				}
				if err := found.ParseFlags(rest); err != nil {
					t.Errorf("%s: %q: %v", path, line, err)
					continue
				}
				if found.Args != nil {
					if err := found.Args(found, found.Flags().Args()); err != nil {
						t.Errorf("%s: %q: %v", path, line, err)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 10 {
		t.Errorf("found only %d commands in the docs", seen)
	}
}

// shellWords splits a command line as a shell would, for the simple
// quoting the docs use.
func shellWords(s string) []string {
	var out []string
	var b strings.Builder
	quote := rune(0)
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			b.WriteRune(r)
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				out = append(out, b.String())
				b.Reset()
				inWord = false
			}
		default:
			b.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, b.String())
	}
	return out
}
