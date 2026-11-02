package sitelinks

import (
	"encoding/json"
	"sort"
	"strings"
)

type caddyRoute struct {
	Match []struct {
		Host []string `json:"host"`
	} `json:"match"`
	Handle []caddyHandler `json:"handle"`
}

type caddyHandler struct {
	Handler   string `json:"handler"`
	Upstreams []struct {
		Dial string `json:"dial"`
	} `json:"upstreams"`
	Routes []caddyRoute `json:"routes"`
}

// caddyJSON reads Caddy's live settings (GET /config/): each route's hosts
// and the upstreams of its reverse_proxy handlers, in subroutes too.
func caddyJSON(b []byte) []upstream {
	var conf struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []caddyRoute `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if json.Unmarshal(b, &conf) != nil {
		return nil
	}
	var out []upstream
	var walk func(routes []caddyRoute, hosts []string, depth int)
	walk = func(routes []caddyRoute, hosts []string, depth int) {
		if depth > 8 {
			return
		}
		for _, r := range routes {
			own := hosts
			var named []string
			for _, m := range r.Match {
				named = append(named, m.Host...)
			}
			if len(named) > 0 {
				own = named
			}
			for _, h := range r.Handle {
				switch h.Handler {
				case "reverse_proxy":
					for _, u := range h.Upstreams {
						host, port := splitHostPort(u.Dial)
						for _, site := range own {
							out = append(out, upstream{site: site, host: host, port: port})
						}
					}
				case "subroute":
					walk(h.Routes, own, depth+1)
				}
			}
		}
	}
	for _, name := range sortedServerNames(conf.Apps.HTTP.Servers) {
		walk(conf.Apps.HTTP.Servers[name].Routes, nil, 0)
	}
	return out
}

func sortedServerNames[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// caddyfile reads a Caddyfile's site blocks: their addresses, and the
// upstreams of each reverse_proxy inside them (in handle and route blocks
// too, and the to lines of a reverse_proxy block). Snippets and the global
// options block are skipped.
func caddyfile(text string) []upstream {
	var out []upstream
	var sites []string
	depth := 0
	inProxy := -1 // the depth of an open reverse_proxy block
	skip := -1    // the depth of a skipped block: a snippet or the global options
	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		opens := strings.HasSuffix(line, "{")
		body := strings.TrimSpace(strings.TrimSuffix(line, "{"))
		if line == "}" {
			depth--
			if depth == inProxy {
				inProxy = -1
			}
			if depth == skip {
				skip = -1
			}
			if depth == 0 {
				sites = nil
			}
			continue
		}
		if depth == 0 {
			if opens {
				if body == "" || strings.HasPrefix(body, "(") {
					skip = 0
				} else {
					sites = nil
					for _, a := range strings.FieldsFunc(body, func(r rune) bool { return r == ',' || r == ' ' }) {
						if h := siteOfAddress(a); h != "" {
							sites = append(sites, h)
						}
					}
				}
				depth++
			}
			continue
		}
		if skip >= 0 {
			if opens {
				depth++
			}
			continue
		}
		f := strings.Fields(body)
		switch {
		case len(f) > 0 && f[0] == "reverse_proxy":
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "@") || a == "*" {
					continue
				}
				host, port := splitHostPort(a)
				for _, s := range sites {
					out = append(out, upstream{site: s, host: host, port: port})
				}
			}
			if opens {
				inProxy = depth
			}
		case inProxy >= 0 && depth == inProxy+1 && len(f) > 1 && f[0] == "to":
			for _, a := range f[1:] {
				host, port := splitHostPort(a)
				for _, s := range sites {
					out = append(out, upstream{site: s, host: host, port: port})
				}
			}
		}
		if opens {
			depth++
		}
	}
	return out
}
