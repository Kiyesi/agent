package pullcheck

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kiyesi/kiyesi/agent/internal/mask"
)

// line is one line of a file, by its 1-based number in the head version.
type line struct {
	n int
	s string
}

// text is a file's lines as the rules read them: cut at MaxLine.
type text struct {
	after, before []string
	hasAfter      bool
	hasBefore     bool
	// added are the lines the change adds.
	added []line
	// view is the head's lines a patch shows, when there is no whole file.
	view map[int]string
	cut  bool
}

func newText(f File) *text {
	t := &text{}
	if f.After != nil {
		t.hasAfter = true
		t.after = t.split(*f.After)
	}
	if f.Before != nil {
		t.hasBefore = true
		t.before = t.split(*f.Before)
	}
	switch {
	case t.hasAfter && t.hasBefore:
		old := make(map[string]bool, len(t.before))
		for _, l := range t.before {
			old[l] = true
		}
		for i, l := range t.after {
			if !old[l] {
				t.added = append(t.added, line{i + 1, l})
			}
		}
	case t.hasAfter && (f.Status == "added" || f.Status == "" || f.Patch == ""):
		for i, l := range t.after {
			t.added = append(t.added, line{i + 1, l})
		}
	default:
		t.fromPatch(f.Patch)
	}
	return t
}

// split cuts a file into lines, each at most MaxLine bytes.
func (t *text) split(s string) []string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		l = strings.TrimSuffix(l, "\r")
		if len(l) > MaxLine {
			l = cutAt(l, MaxLine)
			t.cut = true
		}
		lines[i] = l
	}
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// cutAt shortens s to at most n bytes, on a character boundary.
func cutAt(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// fromPatch reads a unified diff's hunks: the lines added, by their
// number in the head version, and every head line it shows.
func (t *text) fromPatch(patch string) {
	t.view = map[int]string{}
	n := 0
	in := false
	for _, l := range t.split(patch) {
		switch {
		case strings.HasPrefix(l, "@@"):
			n, in = hunkStart(l), true
		case !in:
			// Headers before the first hunk: diff --git, ---, +++.
		case strings.HasPrefix(l, "+"):
			t.added = append(t.added, line{n, l[1:]})
			t.view[n] = l[1:]
			n++
		case strings.HasPrefix(l, " "):
			t.view[n] = l[1:]
			n++
		case l == "":
			// An empty context line some tools write without its space.
			t.view[n] = ""
			n++
		}
	}
}

// hunkStart reads the head's first line from "@@ -a,b +c,d @@".
func hunkStart(h string) int {
	i := strings.Index(h, " +")
	if i < 0 {
		return 1
	}
	rest := h[i+2:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 0 {
		return 1
	}
	return n
}

// at is the head's line n, when the file or the patch shows it.
func (t *text) at(n int) (string, bool) {
	if t.hasAfter {
		if n >= 1 && n <= len(t.after) {
			return t.after[n-1], true
		}
		return "", false
	}
	s, ok := t.view[n]
	return s, ok
}

// snippet is lines start to end of the head, at most 6 lines and 400
// characters, secrets masked and invisible characters written out.
func (t *text) snippet(start, end int) string {
	if start <= 0 {
		return ""
	}
	if end < start {
		end = start
	}
	if end > start+5 {
		end = start + 5
	}
	var lines []string
	for n := start; n <= end; n++ {
		if s, ok := t.at(n); ok {
			lines = append(lines, s)
		}
	}
	return cleanSnippet(strings.Join(lines, "\n"))
}

// cleanSnippet masks secrets, writes out invisible characters and keeps
// the first 400 characters.
func cleanSnippet(s string) string {
	s = strings.ReplaceAll(mask.String(cutAt(s, 4*MaxLine)), mask.Masked, "****")
	s = escapeInvisible(s)
	if utf8.RuneCountInString(s) > 400 {
		r := []rune(s)
		s = string(r[:400])
	}
	return s
}

// escapeInvisible writes characters that cannot be seen as <U+200B>,
// keeping line ends and tabs.
func escapeInvisible(s string) string { return escapeRunes(s, true) }

func escapeRunes(s string, keepLines bool) string {
	var b strings.Builder
	for _, r := range s {
		if hiddenRune(r) && !(keepLines && (r == '\n' || r == '\t')) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hiddenRune is a character a reader cannot see: a control or format
// character, or a variation selector.
func hiddenRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// displayPath writes control characters in a file name out, so a name
// cannot break a line of the output or of a report.
func displayPath(p string) string {
	clean := true
	for _, r := range p {
		if hiddenRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return p
	}
	return escapeRunes(p, false)
}

// normalise trims a line and collapses its white space, for fingerprints.
func normalise(lines ...string) string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return strings.Join(out, "\n")
}

// Magic numbers of compressed and binary files.
var magic = [][]byte{
	{0x1f, 0x8b},                         // gzip
	[]byte("PK\x03\x04"),                 // zip, jar, wheel
	[]byte("BZh"),                        // bzip2
	{0xfd, '7', 'z', 'X', 'Z', 0x00},     // xz
	{0x28, 0xb5, 0x2f, 0xfd},             // zstd
	{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c},   // 7-zip
	[]byte("Rar!\x1a\x07"),               // rar
	{0x89, 'P', 'N', 'G'},                // png
	{0x7f, 'E', 'L', 'F'},                // executables
	{0xcf, 0xfa, 0xed, 0xfe},             // mach-o
	{0x00, 0x61, 0x73, 0x6d},             // wasm
	{0x04, 0x22, 0x4d, 0x18},             // lz4
	[]byte("\xff\xd8\xff"),               // jpeg
	[]byte("GIF8"),                       // gif
	{0xca, 0xfe, 0xba, 0xbe},             // java class
	[]byte("MZ\x90\x00"),                 // windows executables
	[]byte("\x1f\x9d"),                   // compress
	[]byte("\xed\xab\xee\xdb"),           // rpm
	[]byte("!<arch>\n"),                  // deb, static libraries
	{0x50, 0x4b, 0x05, 0x06},             // empty zip
	[]byte("SQLite format 3\x00"),        // sqlite
	{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1}, // office files
}

// looksBinary says a file is binary or compressed: a NUL byte near its
// start, or the magic number of an archive or a program. A patch's first
// added line counts as its start.
func looksBinary(s string) bool {
	if s == "" {
		return false
	}
	head := s[:min(len(s), 8000)]
	if strings.IndexByte(head, 0) >= 0 {
		return true
	}
	starts := []string{s}
	if strings.HasPrefix(s, "@@") {
		if i := strings.Index(s, "\n+"); i >= 0 {
			starts = append(starts, s[i+2:])
		}
	}
	for _, st := range starts {
		for _, m := range magic {
			if bytes.HasPrefix([]byte(st[:min(len(st), 16)]), m) {
				// "BZh" starts words too: bzip2 has a block size digit after it.
				if string(m) == "BZh" && (len(st) < 4 || st[3] < '1' || st[3] > '9') {
					continue
				}
				return true
			}
		}
	}
	return false
}

// locate finds a package in the head's lines: the first line that names
// it, with its version (or other mark) on that line or a few after.
// It returns 0, 0 when the name is not there.
func (t *text) locate(name, mark string) (start, end int) {
	if !t.hasAfter || name == "" {
		return 0, 0
	}
	first := 0
	tries := 0
	for i, l := range t.after {
		if !hasToken(l, name, nameChar) {
			continue
		}
		if first == 0 {
			first = i + 1
		}
		if mark == "" {
			return i + 1, i + 1
		}
		for j := i; j < len(t.after) && j <= i+8; j++ {
			if hasToken(t.after[j], mark, versionChar) {
				return i + 1, j + 1
			}
		}
		if tries++; tries > 500 {
			break
		}
	}
	return first, first
}

func nameChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == '@'
}

func versionChar(b byte) bool {
	return b >= '0' && b <= '9' || b == '.' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// hasToken says s holds tok with no name or version character either side
// (a version may follow a v, as go.sum writes it).
func hasToken(s, tok string, part func(byte) bool) bool {
	from := 0
	for {
		i := strings.Index(s[from:], tok)
		if i < 0 {
			return false
		}
		i += from
		left := i == 0 || !part(s[i-1]) || (s[i-1] == 'v' && tok[0] >= '0' && tok[0] <= '9')
		j := i + len(tok)
		// A scope's @ starts a name; after one, an @ starts its version.
		right := j >= len(s) || !part(s[j]) || s[j] == '@'
		if left && right {
			return true
		}
		from = i + 1
	}
}

// lineWith is the first head line from `from` on that holds sub, or 0.
func (t *text) lineWith(sub string, from int) int {
	if sub == "" {
		return 0
	}
	if !t.hasAfter {
		for _, a := range t.added {
			if a.n >= from && strings.Contains(a.s, sub) {
				return a.n
			}
		}
		return 0
	}
	for i := max(from-1, 0); i < len(t.after); i++ {
		if strings.Contains(t.after[i], sub) {
			return i + 1
		}
	}
	return 0
}

// jsonTooDeep says a JSON text nests deeper than limit, without parsing it.
func jsonTooDeep(s string, limit int) bool {
	depth := 0
	inString, escaped := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{', '[':
			if depth++; depth > limit {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
}
