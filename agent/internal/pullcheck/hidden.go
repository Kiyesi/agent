package pullcheck

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// invisible lists what a line hides: characters that cannot be seen, and
// characters that reverse the direction text is shown in. Joiners inside
// emoji and non-Latin words, the byte order mark at a file's start, flag
// emoji's tag characters and single variation selectors are normal.
func invisible(s string, fileStart bool) (found []rune) {
	rs := []rune(s)
	seen := map[rune]bool{}
	hit := func(r rune) {
		if !seen[r] {
			seen[r] = true
			found = append(found, r)
		}
	}
	isSelector := func(r rune) bool { return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) }
	flag := false
	selectors := 0
	for i, r := range rs {
		if isSelector(r) {
			if selectors++; selectors >= 3 {
				hit(r)
			}
			continue
		}
		selectors = 0
		switch {
		case r == 0x1F3F4:
			flag = true
			continue
		case r >= 0xE0000 && r <= 0xE007F:
			if flag && r >= 0xE0020 {
				if r == 0xE007F {
					flag = false
				}
				continue
			}
			hit(r)
		case r == 0x200C || r == 0x200D:
			if i > 0 && i+1 < len(rs) && rs[i-1] > 0x7F && rs[i+1] > 0x7F && !zeroWidth(rs[i-1]) && !zeroWidth(rs[i+1]) {
				continue
			}
			hit(r)
		case r >= 0x200B && r <= 0x200F, r >= 0x2060 && r <= 0x2064:
			hit(r)
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			hit(r)
		case r == 0xFEFF:
			if !(fileStart && i == 0) {
				hit(r)
			}
		}
		flag = false
	}
	return found
}

func zeroWidth(r rune) bool {
	return (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x2069) || r == 0xFEFF
}

var (
	escapeRuns = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){20,}|(?:\\u[0-9a-fA-F]{4}){20,}|(?:\\[0-7]{3}){20,}|String\.fromCharCode\(\s*(?:\d+\s*,\s*){19,}`)
	runner     = regexp.MustCompile(`(?:^|[^.\w])(eval|exec|Function|execSync|spawnSync|spawn|compile|__import__|system|assert)\s*\(|\bnew\s+(Function)\s*\(|\b(child_process)\b|\b(subprocess)\.\w+|\b(os\.(?:system|popen))\s*\(|\b((?:sh|bash|zsh)\s+-c)\b|\b(powershell(?:\.exe)?)\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\b|\b(base64\s+(?:-d|--decode))\b[^\n]*\|\s*(?:sh|bash)|\b(marshal\.loads|pickle\.loads)\s*\(|\b(vm\.run\w*)\s*\(`)
)

// encoded says a line holds a long encoded block: base64 or hex of 200
// characters or more, or a run of escapes or character codes.
func encoded(s string) bool {
	if escapeRuns.MatchString(s) {
		return true
	}
	run, digit, upper, lower, hex := 0, false, false, false, true
	for i := 0; i <= len(s); i++ {
		var b byte
		if i < len(s) {
			b = s[i]
		}
		switch {
		case b >= '0' && b <= '9':
			digit = true
		case b >= 'A' && b <= 'Z':
			upper = true
			hex = hex && b <= 'F'
		case b >= 'a' && b <= 'z':
			lower = true
			hex = hex && b <= 'f'
		case b == '+' || b == '/' || b == '_' || b == '-':
			hex = false
		default:
			if run >= 200 && ((digit && upper && lower) || hex) {
				return true
			}
			run, digit, upper, lower, hex = 0, false, false, false, true
			continue
		}
		run++
	}
	return false
}

// runnerIn names what runs code in a line, or "".
func runnerIn(s string) string {
	m := runner.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return strings.TrimSpace(m[0])
}

// hidden finds invisible characters and encoded blocks that are run, in
// the lines the change adds.
func (c *checker) hidden(p string, t *text) {
	type hit struct {
		l     line
		runes []rune
	}
	var hits []hit
	for i, a := range t.added {
		if i%1024 == 0 && c.ctx.Err() != nil {
			return
		}
		if rs := invisible(a.s, a.n == 1); len(rs) > 0 {
			hits = append(hits, hit{a, rs})
		}
	}
	// Lines next to each other are one finding.
	for i := 0; i < len(hits); {
		j := i
		for j+1 < len(hits) && hits[j+1].l.n == hits[j].l.n+1 && j+1-i < 6 {
			j++
		}
		var runes []rune
		var lines []string
		for _, h := range hits[i : j+1] {
			runes = append(runes, h.runes...)
			lines = append(lines, h.l.s)
		}
		start, end := hits[i].l.n, hits[j].l.n
		title, how, fix := c.words("hidden-invisible", map[string]string{"file": p, "chars": describe(runes)})
		c.add(Finding{
			Rule: RuleHidden, Title: title, File: p, Start: start, End: end, Snippet: t.snippet(start, end),
			How: how, Fix: fix, Fingerprint: fingerprint(RuleHidden, p, normalise(lines...)),
		})
		i = j + 1
	}
	const near = 10
	for i, a := range t.added {
		if i%1024 == 0 && c.ctx.Err() != nil {
			return
		}
		if !encoded(a.s) {
			continue
		}
		for j := max(0, i-near); j < len(t.added) && j <= i+near; j++ {
			r := t.added[j]
			if r.n-a.n > near || a.n-r.n > near {
				continue
			}
			name := runnerIn(r.s)
			if name == "" {
				continue
			}
			start, end := min(a.n, r.n), max(a.n, r.n)
			lines := []string{a.s}
			if r.n != a.n {
				lines = append(lines, r.s)
			}
			title, how, fix := c.words("hidden-encoded", map[string]string{"file": p, "runner": name})
			c.add(Finding{
				Rule: RuleHidden, Title: title, File: p, Start: start, End: end, Snippet: t.snippet(start, end),
				How: how, Fix: fix, Fingerprint: fingerprint(RuleHidden, p, normalise(lines...)),
			})
			break
		}
	}
}

// describe names the characters found, such as "invisible characters
// (U+200B)".
func describe(runes []rune) string {
	seen := map[rune]bool{}
	var dir, inv []string
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })
	for _, r := range runes {
		if seen[r] {
			continue
		}
		seen[r] = true
		code := fmt.Sprintf("U+%04X", r)
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			dir = append(dir, code)
		} else {
			inv = append(inv, code)
		}
	}
	list := func(codes []string) string {
		if len(codes) > 4 {
			codes = append(codes[:4], "more")
		}
		return strings.Join(codes, ", ")
	}
	var parts []string
	if len(dir) > 0 {
		parts = append(parts, "direction-reversing characters ("+list(dir)+")")
	}
	if len(inv) > 0 {
		parts = append(parts, "invisible characters ("+list(inv)+")")
	}
	return strings.Join(parts, " and ")
}
