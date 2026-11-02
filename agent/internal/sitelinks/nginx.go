package sitelinks

import (
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// directive is one nginx directive, with its block when it has one.
type directive struct {
	name  string
	args  []string
	block []directive
	open  bool
}

// parseNginx reads nginx's settings into directives. Quotes are kept
// simple: a quoted argument loses its quotes.
func parseNginx(text string) []directive {
	var toks []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		var cur strings.Builder
		flush := func() {
			if cur.Len() > 0 {
				toks = append(toks, strings.Trim(cur.String(), `"'`))
				cur.Reset()
			}
		}
		for _, r := range line {
			switch r {
			case ' ', '\t', '\r':
				flush()
			case '{', '}', ';':
				flush()
				toks = append(toks, string(r))
			default:
				cur.WriteRune(r)
			}
		}
		flush()
	}
	pos := 0
	var parse func(depth int) []directive
	parse = func(depth int) []directive {
		var out []directive
		var cur []string
		for pos < len(toks) {
			t := toks[pos]
			pos++
			switch t {
			case ";":
				if len(cur) > 0 {
					out = append(out, directive{name: cur[0], args: cur[1:]})
				}
				cur = nil
			case "{":
				d := directive{open: true}
				if len(cur) > 0 {
					d.name, d.args = cur[0], cur[1:]
				}
				cur = nil
				if depth < 12 {
					d.block = parse(depth + 1)
				}
				out = append(out, d)
			case "}":
				return out
			default:
				cur = append(cur, t)
			}
		}
		return out
	}
	return parse(0)
}

// nginx reads the server blocks of nginx's settings files: each
// server_name and the addresses its proxy_pass lines send to, through an
// upstream block or a variable set in the server when they name one.
func nginx(texts []string) []upstream {
	var all []directive
	for _, t := range texts {
		all = append(all, parseNginx(t)...)
	}
	upstreams := map[string][]string{}
	var servers []directive
	var walk func(ds []directive)
	walk = func(ds []directive) {
		for _, d := range ds {
			switch {
			case d.name == "upstream" && d.open && len(d.args) == 1:
				for _, s := range d.block {
					if s.name == "server" && !s.open && len(s.args) > 0 {
						upstreams[d.args[0]] = append(upstreams[d.args[0]], s.args[0])
					}
				}
			case d.name == "server" && d.open:
				servers = append(servers, d)
			default:
				walk(d.block)
			}
		}
	}
	walk(all)
	var out []upstream
	for _, srv := range servers {
		var names []string
		vars := map[string]string{}
		var passes []string
		var find func(ds []directive)
		find = func(ds []directive) {
			for _, d := range ds {
				switch {
				case d.name == "server_name":
					names = append(names, d.args...)
				case d.name == "set" && len(d.args) == 2:
					vars[d.args[0]] = d.args[1]
				case d.name == "proxy_pass" && len(d.args) == 1:
					passes = append(passes, d.args[0])
				}
				find(d.block)
			}
		}
		find(srv.block)
		for _, p := range passes {
			if v, ok := vars[p]; ok {
				p = v
			}
			addrs := []string{p}
			host, port := splitHostPort(p)
			if list, ok := upstreams[host]; ok && (port == 0 || port == 80 || port == 443) {
				addrs = list
			}
			for _, a := range addrs {
				h, n := splitHostPort(a)
				if !strings.Contains(a, "://") && n == 0 {
					n = 80
				}
				for _, s := range names {
					out = append(out, upstream{site: s, host: h, port: n})
				}
			}
		}
	}
	return out
}

// nginxFiles are the texts of nginx's settings: the server's own, and
// those mounted into an nginx container, by their path on the server.
// Includes are not followed; the usual folders are read instead.
func nginxFiles(fsys fs.FS, cs []system.Container) []string {
	dirs := []string{"etc/nginx"}
	var files []string
	for _, c := range cs {
		if !strings.Contains(strings.ToLower(c.Image), "nginx") {
			continue
		}
		for i := 0; i+1 < len(c.Mounts); i += 2 {
			src, dst := strings.TrimPrefix(c.Mounts[i], "/"), c.Mounts[i+1]
			switch {
			case src == "" || !strings.HasPrefix(dst, "/etc/nginx"):
			case dst == "/etc/nginx":
				dirs = append(dirs, src)
			case dst == "/etc/nginx/conf.d" || dst == "/etc/nginx/sites-enabled":
				files = append(files, confsIn(fsys, src)...)
			default:
				files = append(files, src)
			}
		}
	}
	for _, d := range dirs {
		files = append(files, path.Join(d, "nginx.conf"))
		files = append(files, confsIn(fsys, path.Join(d, "conf.d"))...)
		files = append(files, confsIn(fsys, path.Join(d, "sites-enabled"))...)
	}
	var out []string
	read := 0
	for _, f := range dedupe(files) {
		b, err := fs.ReadFile(fsys, f)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		if read += len(b); read > 8<<20 {
			break
		}
		out = append(out, string(b))
	}
	return out
}

// confsIn are the files of a settings folder, sorted, at most 200.
func confsIn(fsys fs.FS, dir string) []string {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if strings.HasSuffix(dir, "conf.d") && !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		out = append(out, path.Join(dir, e.Name()))
	}
	sort.Strings(out)
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}
