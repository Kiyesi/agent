package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every kiyesi command the docs show, and every one a finding's fix names,
// must run as written: a real command, its real flags, and as many words
// after it as it takes. A <placeholder> stands for one word. Nothing runs:
// each line is only parsed, as the program would parse it. Beyond
// TestEveryCommandInTheDocsParses, this reads `code` in the text, commands
// after && or an environment setting, and the pack's fixes.

// fenced is a shell block in a docs page; inline is `code` in its text.
var (
	fenced = regexp.MustCompile("(?s)```(?:sh|bash|shell)[^\n]*\n(.*?)```")
	inline = regexp.MustCompile("`([^`\n]*\\bkiyesi [^`\n]*)`")
	// In the pack's words, a command runs to the first comma, semicolon,
	// colon or bracket that ends it, or to the word that starts the
	// sentence's next part, such as "lists" in "kiyesi keys lists each key".
	inPack       = regexp.MustCompile(`\b(kiyesi [a-z][^,;:()\n"]*?)(?:\s+(?:then|and|or|to|when|on|if|lists|puts|turns|moves|prints|asks|is|takes|can|may|says|which|checks)\b|[,;:()\n"]|$)`)
	placeholders = regexp.MustCompile(`<[^>]+>|\[[^\]]+\]`)
)

func TestEveryKiyesiCommandShownRunsAsWritten(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// named is a command named in a sentence, such as `kiyesi keys remove`:
	// it must exist, with the flags it names, but need not be complete.
	type shown struct {
		where, line string
		named       bool
	}
	var all []shown
	pages, err := filepath.Glob(filepath.Join(root, "site", "src", "content", "docs", "*", "*.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob(filepath.Join(root, "site", "src", "content", "docs", "*.mdx"))
	deeper, _ := filepath.Glob(filepath.Join(root, "site", "src", "content", "docs", "*", "*", "*.mdx"))
	pages = append(append(pages, more...), deeper...)
	if len(pages) < 20 {
		t.Fatalf("found %d docs pages; the docs moved?", len(pages))
	}
	for _, p := range pages {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, p)
		// The changelog tells what each past version did, in its words then.
		if filepath.Base(p) == "changelog.mdx" {
			continue
		}
		text := string(data)
		for _, m := range fenced.FindAllStringSubmatch(text, -1) {
			body := strings.ReplaceAll(m[1], "\\\n", " ")
			for _, l := range strings.Split(body, "\n") {
				all = append(all, shown{rel, l, false})
			}
		}
		for _, m := range inline.FindAllStringSubmatch(fenced.ReplaceAllString(text, ""), -1) {
			all = append(all, shown{rel, m[1], true})
		}
	}
	pack, err := os.ReadFile(filepath.Join(root, "packs", "checks", "en.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range inPack.FindAllStringSubmatch(string(pack), -1) {
		all = append(all, shown{"packs/checks/en.yaml", m[1], false})
	}

	checked := 0
	for _, s := range all {
		for _, args := range kiyesiCommands(s.line) {
			checked++
			if err := parsesAsWritten(args, s.named); err != nil {
				t.Errorf("%s: kiyesi %s: %v", s.where, strings.Join(args, " "), err)
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d kiyesi commands found in the docs and the pack; the reader is broken", checked)
	}
}

// kiyesiCommands finds the kiyesi commands in one line of shell or text,
// as the words after "kiyesi", with each <placeholder> as one word.
func kiyesiCommands(line string) [][]string {
	line = strings.TrimSpace(placeholders.ReplaceAllString(line, "x"))
	if strings.HasPrefix(line, "#") {
		return nil
	}
	if i := strings.Index(line, " #"); i >= 0 {
		line = line[:i]
	}
	var out [][]string
	// Each part of a pipeline or list runs by itself.
	for _, part := range regexp.MustCompile(`\s*(?:\|\||&&|\||;)\s*`).Split(line, -1) {
		words := shellWords(part)
		at := -1
		for i, w := range words {
			if w == "kiyesi" || strings.HasSuffix(w, "/kiyesi") {
				// Only where it runs: after sudo, an env setting or a prompt.
				ok := true
				for _, before := range words[:i] {
					if before != "sudo" && before != "$" && before != "-E" && !strings.Contains(before, "=") {
						ok = false
					}
				}
				if ok {
					at = i
				}
				break
			}
		}
		if at < 0 {
			continue
		}
		var args []string
		for _, w := range words[at+1:] {
			if strings.HasPrefix(w, ">") || strings.HasPrefix(w, "2>") {
				break
			}
			// A shell variable is one word the shell fills in.
			if strings.ContainsAny(w, "$`") {
				w = "x"
			}
			if w == "..." || w == "…" {
				continue
			}
			args = append(args, strings.TrimRight(w, ".…"))
		}
		out = append(out, args)
	}
	return out
}

// parsesAsWritten finds the command, reads its flags and checks the number
// of words after it, as running it would, without running it. For a
// command only named, the command and the flags it names must exist.
func parsesAsWritten(args []string, named bool) error {
	root := newRoot(IO{Out: io.Discard, Err: io.Discard})
	root.InitDefaultCompletionCmd()
	cmd, rest, err := root.Find(args)
	if err != nil {
		return err
	}
	if cmd == root && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		return fmt.Errorf("unknown command %q", rest[0])
	}
	if named {
		for _, w := range rest {
			if w == "--" {
				break
			}
			name, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
			if strings.HasPrefix(w, "--") && cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil && name != "help" {
				return fmt.Errorf("unknown flag --%s", name)
			}
		}
		return nil
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return err
	}
	if help, _ := cmd.Flags().GetBool("help"); help {
		return nil
	}
	return cmd.ValidateArgs(cmd.Flags().Args())
}

// Versions are written in full, as kiyesi version prints them: 0.39.0, never
// 0.39, in the docs, the website, the dashboard and each page's "last tested".
func TestVersionsAreWrittenInFull(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	short := regexp.MustCompile(`(?i)\b(?:kiyesi|agent|version|than|from|before|after)[ :]+'?(\d+\.\d+)\b(?:[^.\d]|$)`)
	var files []string
	for _, pattern := range []string{
		"site/src/content/docs/*.mdx", "site/src/content/docs/*/*.mdx", "site/src/content/docs/*/*/*.mdx",
		"web/src/pages/*.astro", "web/src/pages/*/*.astro", "web/src/components/*.astro",
		"dashboard/src/messages/en.json",
		// What the program and the service say to people.
		"agent/internal/cli/*.go", "agent/internal/render/*.go", "api/src/features/*/*.ts",
	} {
		m, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 30 {
		t.Fatalf("found %d files; did they move?", len(files))
	}
	lastTested := regexp.MustCompile(`(?m)^lastTested:\n\s+version: '?([^'\n]+)'?`)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, f)
		if strings.HasSuffix(f, "_test.go") || strings.Contains(f, ".test.") {
			continue
		}
		text := string(data)
		if strings.HasSuffix(f, ".go") || strings.HasSuffix(f, ".ts") {
			// In code, only what people read: strings, not comments.
			text = regexp.MustCompile(`(?m)^\s*(//|/?\*).*$`).ReplaceAllString(text, "")
		}
		for _, m := range short.FindAllStringSubmatch(text, -1) {
			t.Errorf("%s: %q: write the version in full, such as %s.0", rel, strings.TrimSpace(m[0]), m[1])
		}
		for _, m := range lastTested.FindAllStringSubmatch(text, -1) {
			if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(m[1]) {
				t.Errorf("%s: last tested with %q: write the version in full", rel, m[1])
			}
		}
	}
}
