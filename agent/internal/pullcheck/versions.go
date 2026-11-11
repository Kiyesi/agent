package pullcheck

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

// The version and name rules below are a port of
// api/src/features/malware/list.ts (compareVersions, covers, nameKey). They
// must give the same answers: testdata/versions.json holds the cases both
// sides test.

// Range is one range of versions a report covers.
type Range struct {
	Introduced   string  `json:"introduced"`
	Fixed        *string `json:"fixed,omitempty"`
	LastAffected *string `json:"lastAffected,omitempty"`
}

// Entry is one report's claim about one package: every version, some, or ranges.
type Entry struct {
	ID       string
	Eco      string
	Name     string
	All      bool
	Versions []string
	Ranges   []Range
}

var pypiRuns = regexp.MustCompile(`[-_.]+`)

// jsSpace is what JavaScript's trim and parseInt skip: white space, line
// ends and the byte order mark.
func jsSpace(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' }

// NameKey is a package's name as its own registry compares it.
func NameKey(eco, name string) string {
	n := strings.TrimFunc(name, jsSpace)
	switch eco {
	// PEP 503: case and runs of "-", "_" and "." do not matter.
	case "PyPI":
		return pypiRuns.ReplaceAllString(jsLower(n), "-")
	case "NuGet", "Packagist", "crates.io", "npm":
		return jsLower(n)
	}
	return n
}

// jsLower lower-cases as JavaScript does for the one letter where Go differs.
func jsLower(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "\u0130", "i\u0307"))
}

// parseIntJS reads the leading digits of s as JavaScript's parseInt(s, 10)
// does, and 0 where it gives NaN.
func parseIntJS(s string) float64 {
	s = strings.TrimLeftFunc(s, jsSpace)
	neg := false
	if s != "" && (s[0] == '-' || s[0] == '+') {
		neg = s[0] == '-'
		s = s[1:]
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(s[:i], 64)
	if err != nil && !math.IsInf(f, 0) {
		return 0
	}
	if neg {
		return -f
	}
	return f
}

type splitVersion struct {
	nums []float64
	pre  string
}

func splitV(v string) splitVersion {
	if v != "" && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	// JavaScript's split(/[-+]/, 2): the text before the first - or +, and
	// the text between it and the next one.
	main, rest := v, ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		main, rest = v[:i], v[i+1:]
		if j := strings.IndexAny(rest, "-+"); j >= 0 {
			rest = rest[:j]
		}
	}
	var nums []float64
	for _, p := range strings.Split(main, ".") {
		nums = append(nums, parseIntJS(p))
	}
	return splitVersion{nums: nums, pre: rest}
}

// lessUTF16 compares as JavaScript's < does on strings: by UTF-16 code units.
func lessUTF16(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// CompareVersions compares dotted versions number by number; words after a
// "-" sort before none. It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	x, y := splitV(a), splitV(b)
	for i := 0; i < max(len(x.nums), len(y.nums)); i++ {
		var p, q float64
		if i < len(x.nums) {
			p = x.nums[i]
		}
		if i < len(y.nums) {
			q = y.nums[i]
		}
		// Two numbers too long to hold are both infinite: JavaScript's
		// difference is NaN, which counts as equal.
		d := p - q
		if d != 0 && !math.IsNaN(d) {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case x.pre == y.pre:
		return 0
	case x.pre == "":
		return 1
	case y.pre == "":
		return -1
	case lessUTF16(x.pre, y.pre):
		return -1
	}
	return 1
}

// Covers says whether an entry covers this version.
func Covers(e Entry, version string) bool {
	if e.All {
		return true
	}
	for _, v := range e.Versions {
		if v == version {
			return true
		}
	}
	for _, r := range e.Ranges {
		if (r.Introduced == "0" || CompareVersions(version, r.Introduced) >= 0) &&
			(r.Fixed == nil || CompareVersions(version, *r.Fixed) < 0) &&
			(r.LastAffected == nil || CompareVersions(version, *r.LastAffected) <= 0) {
			return true
		}
	}
	return false
}
