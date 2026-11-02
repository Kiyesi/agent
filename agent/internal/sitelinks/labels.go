package sitelinks

import (
	"regexp"
	"sort"
	"strings"
)

// hostRule is Host(`a.example.com`) or Host(`a.example.com`, `b.example.com`)
// in a Traefik router's rule; HostRegexp and HostSNI are not it.
var (
	hostRule  = regexp.MustCompile(`\bHost\(([^)]*)\)`)
	hostQuote = regexp.MustCompile("[`\"']([^`\"']+)[`\"']")
)

// TraefikHosts are the hosts named by the HTTP routers' rules in a
// container's Traefik labels, such as
// traefik.http.routers.shop.rule=Host(`shop.example.com`) || Host(`www.shop.example.com`).
// None when the container turns Traefik off for itself.
func TraefikHosts(labels map[string]string) []string {
	if strings.EqualFold(strings.TrimSpace(labels["traefik.enable"]), "false") {
		return nil
	}
	var out []string
	for _, k := range sortedKeys(labels) {
		if !strings.HasPrefix(k, "traefik.http.routers.") || !strings.HasSuffix(k, ".rule") {
			continue
		}
		for _, m := range hostRule.FindAllStringSubmatch(labels[k], -1) {
			for _, q := range hostQuote.FindAllStringSubmatch(m[1], -1) {
				out = append(out, q[1])
			}
		}
	}
	return out
}

// caddyLabel is caddy or caddy_0, caddy_1...: caddy-docker-proxy's site
// address labels.
var caddyLabel = regexp.MustCompile(`^caddy(_\d+)?$`)

// CaddyLabelHosts are the site addresses in a container's
// caddy-docker-proxy labels, such as caddy=shop.example.com,
// www.shop.example.com with caddy.reverse_proxy={{upstreams 8080}}. The
// container carrying them is the one Caddy sends those sites to.
func CaddyLabelHosts(labels map[string]string) []string {
	var out []string
	for _, k := range sortedKeys(labels) {
		if !caddyLabel.MatchString(k) {
			continue
		}
		for _, addr := range strings.FieldsFunc(labels[k], func(r rune) bool { return r == ',' || r == ' ' }) {
			if h := siteOfAddress(addr); h != "" {
				out = append(out, h)
			}
		}
	}
	return out
}

// siteOfAddress is the host of a Caddy site address: "https://a.example.com:443"
// is a.example.com; ":80" and "(snippet)" are none.
func siteOfAddress(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" || strings.HasPrefix(a, "(") || strings.HasPrefix(a, ":") || strings.HasPrefix(a, "{") {
		return ""
	}
	if _, rest, ok := strings.Cut(a, "://"); ok {
		a = rest
	}
	a, _, _ = strings.Cut(a, "/")
	return a
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
