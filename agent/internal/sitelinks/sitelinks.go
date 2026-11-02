// Package sitelinks reads which container serves which site, so a
// container's release is judged on its own sites' requests. It only reads:
// the web servers' labels on each container (Traefik and
// caddy-docker-proxy), Caddy's live settings (a GET to its admin address on
// the server itself), a Caddyfile, and nginx's settings files. It never
// changes anything.
package sitelinks

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/collect"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// Max is the most links sent from one server.
const Max = 200

// Link says that a container serves a site, and where that was read.
type Link struct {
	Site      string `json:"site"`
	Container string `json:"container"`
	// Source is traefik, caddy (its labels or live settings), caddyfile or nginx.
	Source string `json:"source"`
}

// CaddyAdmin is Caddy's admin address on the server itself; it answers on
// localhost only, by default.
var CaddyAdmin = "http://127.0.0.1:2019/config/"

// caddyConfig reads Caddy's live settings with a GET, or nil when Caddy
// does not answer within 2 seconds. A variable, so tests answer for it.
var caddyConfig = func(ctx context.Context) []byte {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CaddyAdmin, nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	return b
}

// upstream is one address a web server sends a site's requests to.
type upstream struct {
	site, host string
	port       int
}

// Read finds the links on a server whose containers are cs. Labels come
// first, then Caddy's live settings (or else its Caddyfile), then nginx;
// a site keeps the first link found.
func Read(ctx context.Context, fsys fs.FS, hostname string, cs []system.Container) []Link {
	out := []Link{}
	seen := map[string]bool{}
	add := func(site, container, source string) {
		site = collect.Site(site)
		if site == "" || container == "" || seen[site] || len(out) >= Max {
			return
		}
		seen[site] = true
		out = append(out, Link{Site: site, Container: container, Source: source})
	}
	running := make([]system.Container, 0, len(cs))
	for _, c := range cs {
		if c.Status == "" || c.Status == "running" {
			running = append(running, c)
		}
	}
	// The labels: the container that carries them serves the hosts they name.
	for _, c := range sortedByName(running) {
		for _, h := range TraefikHosts(c.Labels) {
			add(h, c.Name, "traefik")
		}
		for _, h := range CaddyLabelHosts(c.Labels) {
			add(h, c.Name, "caddy")
		}
	}
	match := func(ups []upstream, source string) {
		for _, u := range ups {
			if name := matchContainer(u.host, u.port, hostname, running); name != "" {
				add(u.site, name, source)
			}
		}
	}
	if b := caddyConfig(ctx); b != nil {
		match(caddyJSON(b), "caddy")
	} else {
		for _, f := range caddyfiles(fsys, running) {
			if b, err := fs.ReadFile(fsys, f); err == nil {
				match(caddyfile(string(b)), "caddyfile")
			}
		}
	}
	match(nginx(nginxFiles(fsys, running)), "nginx")
	return out
}

func sortedByName(cs []system.Container) []system.Container {
	out := append([]system.Container{}, cs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// matchContainer is the container an upstream reaches: by its name, an
// alias or address on its networks, or, for an address on the server
// itself, by a port it publishes. "" when none does.
func matchContainer(host string, port int, hostname string, cs []system.Container) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return ""
	}
	local := host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::1" ||
		(hostname != "" && host == strings.ToLower(hostname))
	for _, c := range sortedByName(cs) {
		if local {
			for _, p := range c.Ports {
				if port > 0 && p.HostPort == port && (p.Proto == "" || p.Proto == "tcp") {
					return c.Name
				}
			}
			continue
		}
		if strings.EqualFold(c.Name, host) || strings.EqualFold(c.ComposeService, host) {
			return c.Name
		}
		for _, a := range c.Aliases {
			if strings.EqualFold(a, host) {
				return c.Name
			}
		}
		for _, ip := range c.IPs {
			if ip == host {
				return c.Name
			}
		}
	}
	return ""
}

// splitHostPort reads "api:8080", "http://api:8080/", "unix//run/x.sock"
// or "localhost" into a host and a port (0 when none is given, and the
// scheme's when there is one).
func splitHostPort(addr string) (string, int) {
	a := strings.TrimSpace(addr)
	port := 0
	switch {
	case strings.HasPrefix(a, "unix/"), strings.HasPrefix(a, "unix:"):
		return "", 0
	case strings.HasPrefix(a, "https://"):
		a, port = strings.TrimPrefix(a, "https://"), 443
	case strings.HasPrefix(a, "http://"):
		a, port = strings.TrimPrefix(a, "http://"), 80
	case strings.Contains(a, "://"):
		_, a, _ = strings.Cut(a, "://")
	}
	a, _, _ = strings.Cut(a, "/")
	if a == "" || strings.ContainsAny(a, "${}") {
		return "", 0
	}
	if h, p, err := net.SplitHostPort(a); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", 0
		}
		return h, n
	}
	return a, port
}

// caddyfiles are the Caddyfiles to read: the server's own, and those
// mounted into a Caddy container, by their path on the server.
func caddyfiles(fsys fs.FS, cs []system.Container) []string {
	var out []string
	if _, err := fs.Stat(fsys, "etc/caddy/Caddyfile"); err == nil {
		out = append(out, "etc/caddy/Caddyfile")
	}
	for _, c := range cs {
		if !strings.Contains(strings.ToLower(c.Image), "caddy") {
			continue
		}
		for i := 0; i+1 < len(c.Mounts); i += 2 {
			src, dst := strings.TrimPrefix(c.Mounts[i], "/"), c.Mounts[i+1]
			switch {
			case src == "":
			case dst == "/etc/caddy/Caddyfile":
				out = append(out, src)
			case dst == "/etc/caddy":
				out = append(out, path.Join(src, "Caddyfile"))
			}
		}
	}
	return dedupe(out)
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	out := list[:0]
	for _, x := range list {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
