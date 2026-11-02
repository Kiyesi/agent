package sitelinks

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withCaddy makes Caddy's admin address answer b (nil: it does not answer).
func withCaddy(t *testing.T, b []byte) {
	t.Helper()
	before := caddyConfig
	caddyConfig = func(context.Context) []byte { return b }
	t.Cleanup(func() { caddyConfig = before })
}

// The containers of a server running a few apps behind a web server.
func containers() []system.Container {
	return []system.Container{
		{
			Name: "shop-web-1", Status: "running", ComposeService: "web", Aliases: []string{"web", "shop-web-1"},
			Labels: map[string]string{
				"traefik.enable":                                      "true",
				"traefik.http.routers.shop.rule":                      "Host(`shop.example.com`) || Host(`WWW.shop.example.com`)",
				"traefik.http.routers.admin.rule":                     "Host(`admin.example.com`, `staff.example.com`) && PathPrefix(`/admin`)",
				"traefik.http.routers.wild.rule":                      "HostRegexp(`{sub:[a-z]+}.example.com`)",
				"traefik.tcp.routers.db.rule":                         "HostSNI(`db.example.com`)",
				"traefik.http.services.shop.loadbalancer.server.port": "3000",
			},
		},
		{
			Name: "blog", Status: "running",
			Labels: map[string]string{
				"caddy":               "blog.example.com, https://news.example.com",
				"caddy.reverse_proxy": "{{upstreams 2368}}",
				"caddy_1":             ":8080",
			},
		},
		{
			Name: "hidden", Status: "running",
			Labels: map[string]string{
				"traefik.enable":              "false",
				"traefik.http.routers.x.rule": "Host(`hidden.example.com`)",
			},
		},
		{
			Name: "api", Status: "running", Aliases: []string{"api"},
			Ports: []system.PublishedPort{{HostIP: "127.0.0.1", HostPort: 3000, Proto: "tcp"}},
		},
		{Name: "billing-app-1", Status: "running", ComposeService: "app", Aliases: []string{"billing"}, IPs: []string{"172.18.0.7"}},
		{
			Name: "caddy", Status: "running", Image: "caddy:2.8-alpine",
			Mounts: []string{"/srv/caddy/Caddyfile", "/etc/caddy/Caddyfile", "/srv/caddy/data", "/data"},
		},
		// A stopped container serves nothing.
		{Name: "old-api", Status: "exited", Ports: []system.PublishedPort{{HostPort: 9999, Proto: "tcp"}}},
	}
}

func bySite(links []Link) map[string]string {
	out := map[string]string{}
	for _, l := range links {
		out[l.Site] = l.Container + " " + l.Source
	}
	return out
}

func TestReadsTraefikAndCaddyLabels(t *testing.T) {
	withCaddy(t, nil)
	got := bySite(Read(context.Background(), fstest.MapFS{}, "web-1", containers()))
	want := map[string]string{
		"shop.example.com":     "shop-web-1 traefik",
		"www.shop.example.com": "shop-web-1 traefik",
		"admin.example.com":    "shop-web-1 traefik",
		"staff.example.com":    "shop-web-1 traefik",
		"blog.example.com":     "blog caddy",
		"news.example.com":     "blog caddy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("links = %v\nwant %v", got, want)
	}
}

func TestReadsCaddysLiveSettings(t *testing.T) {
	withCaddy(t, sample(t, "caddy-config.json"))
	// A Caddyfile is not read when Caddy answers.
	fsys := fstest.MapFS{"etc/caddy/Caddyfile": {Data: []byte("other.example.com {\n\treverse_proxy api:3000\n}\n")}}
	got := bySite(Read(context.Background(), fsys, "web-1", containers()))
	for site, want := range map[string]string{
		"api.example.com":     "api caddy",
		"www.api.example.com": "api caddy",
		"billing.example.com": "billing-app-1 caddy",
		// Read from the labels first.
		"shop.example.com": "shop-web-1 traefik",
	} {
		if got[site] != want {
			t.Errorf("%s = %q, want %q", site, got[site], want)
		}
	}
	// gone:9000 is no container here.
	for _, site := range []string{"ghost.example.com", "other.example.com"} {
		if _, ok := got[site]; ok {
			t.Errorf("%s linked: %v", site, got)
		}
	}
}

func TestReadsACaddyfileMountedIntoCaddysContainer(t *testing.T) {
	withCaddy(t, nil)
	fsys := fstest.MapFS{"srv/caddy/Caddyfile": {Data: sample(t, "Caddyfile")}}
	got := bySite(Read(context.Background(), fsys, "web-1", containers()))
	for site, want := range map[string]string{
		// localhost:3000 is the port api publishes.
		"api.example.com":     "api caddyfile",
		"www.api.example.com": "api caddyfile",
		"billing.example.com": "billing-app-1 caddyfile",
		"docs.example.com":    "billing-app-1 caddyfile",
	} {
		if got[site] != want {
			t.Errorf("%s = %q, want %q", site, got[site], want)
		}
	}
	// 10.0.0.9 is no container here, and a snippet is no site.
	if _, ok := got["old.example.com"]; ok {
		t.Errorf("old.example.com linked: %v", got)
	}
}

func TestReadsNginxServerBlocksThroughUpstreamsAndVariables(t *testing.T) {
	withCaddy(t, nil)
	fsys := fstest.MapFS{
		"etc/nginx/nginx.conf":           {Data: sample(t, "nginx/nginx.conf")},
		"etc/nginx/sites-enabled/status": {Data: sample(t, "nginx/sites-enabled/status")},
		"etc/nginx/conf.d/billing.conf":  {Data: sample(t, "nginx/conf.d/billing.conf")},
		"etc/nginx/conf.d/README":        {Data: sample(t, "nginx/conf.d/README")},
	}
	got := bySite(Read(context.Background(), fsys, "web-1", containers()))
	for site, want := range map[string]string{
		"status.example.com":  "api nginx",
		"metrics.example.com": "api nginx",
		"pay.example.com":     "billing-app-1 nginx",
	} {
		if got[site] != want {
			t.Errorf("%s = %q, want %q", site, got[site], want)
		}
	}
	// 127.0.0.1:9999 belongs to a stopped container; a README is not read.
	for _, site := range []string{"legacy.example.com", "notread.example.com", "_"} {
		if _, ok := got[site]; ok {
			t.Errorf("%s linked: %v", site, got)
		}
	}
}

func TestMatchesUpstreamsToContainers(t *testing.T) {
	cs := containers()
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"api", 3000, "api"},
		{"web", 3000, "shop-web-1"},
		{"app", 80, "billing-app-1"},
		{"billing", 8080, "billing-app-1"},
		{"172.18.0.7", 8080, "billing-app-1"},
		{"127.0.0.1", 3000, "api"},
		{"localhost", 3000, "api"},
		{"web-1", 3000, "api"},
		{"localhost", 4000, ""},
		{"elsewhere.example.com", 443, ""},
		{"", 80, ""},
	} {
		if got := matchContainer(c.host, c.port, "web-1", cs); got != c.want {
			t.Errorf("%s:%d = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestSplitsUpstreamAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"api:3000":               "api 3000",
		"http://api:3000/v1":     "api 3000",
		"http://api":             "api 80",
		"https://api":            "api 443",
		"h2c://grpc:50051":       "grpc 50051",
		"[::1]:8080":             "::1 8080",
		"unix//run/app.sock":     " 0",
		"http://$backend":        " 0",
		"{http.reverse_proxy.x}": " 0",
	} {
		h, p := splitHostPort(in)
		if got := fmt.Sprintf("%s %d", h, p); got != want {
			t.Errorf("%s = %q, want %q", in, got, want)
		}
	}
}

func TestSendsAtMost200Links(t *testing.T) {
	withCaddy(t, nil)
	labels := map[string]string{}
	for i := range 300 {
		labels[fmt.Sprintf("traefik.http.routers.r%d.rule", i)] = fmt.Sprintf("Host(`s%d.example.com`)", i)
	}
	links := Read(context.Background(), fstest.MapFS{}, "", []system.Container{{Name: "many", Labels: labels}})
	if len(links) != Max {
		t.Errorf("%d links", len(links))
	}
}

func TestNoContainersNoLinks(t *testing.T) {
	withCaddy(t, sample(t, "caddy-config.json"))
	if links := Read(context.Background(), fstest.MapFS{}, "", nil); len(links) != 0 {
		t.Errorf("links = %v", links)
	}
}
