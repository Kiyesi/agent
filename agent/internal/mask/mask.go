// Package mask removes secrets from text before anything leaves the server.
// It is applied to every value the agent sends, and the API applies the
// same rules again on what it receives. A masked secret becomes [masked]:
// the report can still say a secret is there, never what it is.
package mask

import (
	"reflect"
	"regexp"
)

// Masked replaces every secret.
const Masked = "[masked]"

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Passwords in addresses: scheme://user:password@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]*:)[^/\s@]+@`), "${1}" + Masked + "@"},
	// Private keys, whole blocks.
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`), Masked},
	// Settings whose name says they hold a secret: KEY=value, KEY: value, "key": "value".
	{regexp.MustCompile(`(?i)(["']?[a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|session|cookie)[a-z0-9_.\-]*["']?\s*[:=]\s*["']?)([^\s"',;&]{3,})`), "${1}" + Masked},
	// Authorization headers.
	{regexp.MustCompile(`(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)?\s*)([A-Za-z0-9._~+/=\-]{8,})`), "${1}" + Masked},
	{regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=\-]{12,}`), "${1} " + Masked},
	// Well-known token shapes, wherever they appear.
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), Masked},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_\w{40,}`), Masked},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`), Masked},
	{regexp.MustCompile(`\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b`), Masked},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), Masked},
	// Passwords given to command-line tools: redis-cli -a pw, mysql -ppw,
	// --password pw, PGPASSWORD=pw.
	{regexp.MustCompile(`(\bredis-cli\b[^\n]*?\s-a\s+)("[^"]*"|'[^']*'|\S+)`), "${1}" + Masked},
	{regexp.MustCompile(`(\b(?:mysql|mysqldump|mariadb)\b[^\n]*?\s-p)([^\s-][^\s]*)`), "${1}" + Masked},
	{regexp.MustCompile(`(?i)(--pass(?:word)?\s+)("[^"]*"|'[^']*'|\S+)`), "${1}" + Masked},
	// Query strings that carry secrets: ?token=..., &key=...
	{regexp.MustCompile(`(?i)([?&](?:token|key|secret|password|sig|signature|access_token|api_key)=)[^&\s#]+`), "${1}" + Masked},
}

// String masks every secret in s.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Value masks every string inside v, in place. v must be a pointer. It
// walks structs, slices, arrays and maps of any depth.
func Value(v any) {
	walk(reflect.ValueOf(v))
}

func walk(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			if v.Kind() == reflect.Interface && v.Elem().Kind() == reflect.String {
				if v.CanSet() {
					v.Set(reflect.ValueOf(String(v.Elem().String())))
				}
				return
			}
			walk(v.Elem())
		}
	case reflect.Struct:
		for i := range v.NumField() {
			// An unexported field is never sent (JSON leaves it out), and
			// reflection may not change it.
			if !v.Type().Field(i).IsExported() {
				continue
			}
			if v.Field(i).CanSet() || v.Field(i).Kind() != reflect.String {
				walk(v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walk(v.Index(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			e := v.MapIndex(k)
			switch e.Kind() {
			case reflect.String:
				v.SetMapIndex(k, reflect.ValueOf(String(e.String())).Convert(e.Type()))
			case reflect.Interface:
				if !e.IsNil() && e.Elem().Kind() == reflect.String {
					v.SetMapIndex(k, reflect.ValueOf(String(e.Elem().String())))
				} else if !e.IsNil() {
					walk(e.Elem())
				}
			default:
				cp := reflect.New(e.Type()).Elem()
				cp.Set(e)
				walk(cp)
				v.SetMapIndex(k, cp)
			}
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(String(v.String()))
		}
	}
}
