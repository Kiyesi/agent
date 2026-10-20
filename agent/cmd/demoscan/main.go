// Command demoscan prints the sample scans for the demo at demo.kiyesi.dev:
// five made-up servers, each with chosen results, put into words by the
// same pack and graded the same way as a real scan. Never shipped.
//
//	go run ./cmd/demoscan -now 2026-10-18T12:00:00Z > scans.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

const home = "DE"

// The same on every server unless a server says otherwise.
var shared = map[string]map[string]string{
	"disk":    {"limit": "80"},
	"updates": {"limit": "7"},
}

type server struct {
	name, os string
	// results by check id; a check not listed here passes with pass[id].
	results map[string]checks.Result
	pass    map[string]map[string]string
}

func f(key string, vars map[string]string) checks.Finding { return checks.Found(key, vars) }

func place(kind, name, city, country, provider string) checks.Location {
	return checks.Location{Kind: kind, Name: name, Place: city, Country: country, Confidence: "confirmed", Provider: provider}
}

func main() {
	at := flag.String("now", "", "the scans' time, RFC 3339")
	flag.Parse()
	now, err := time.Parse(time.RFC3339, *at)
	if err != nil {
		fmt.Fprintln(os.Stderr, "give -now as RFC 3339")
		os.Exit(2)
	}
	pack, err := packs.English()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	killed := now.Add(-50 * time.Hour).Truncate(time.Minute)
	frankfurt := func(name string) checks.Result {
		r := checks.Pass(map[string]string{"place": "Frankfurt", "home": "Germany"})
		r.Locations = []checks.Location{place("Server", name, "Frankfurt, Germany", "DE", "DigitalOcean")}
		return r
	}
	servers := []server{
		{
			name: "checkout-api-prod", os: "Ubuntu 24.04 LTS",
			results: map[string]checks.Result{
				"exposed-databases": checks.Fail(f("open", map[string]string{"database": "Redis", "port": "6379", "service": "redis"})),
				"ssh":               checks.Fail(f("password", nil)),
				"server-location":   frankfurt("checkout-api-prod"),
				"database-connections": func() checks.Result {
					r := checks.Pass(map[string]string{"count": "2", "home": "Germany"})
					r.Locations = []checks.Location{
						{Kind: "Database", Name: "orders (checkout-db-prod)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed", Private: true, Payment: true, Host: "10.114.0.4"},
						{Kind: "Database", Name: "redis (this server)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed"},
					}
					return r
				}(),
				"backup-destinations": func() checks.Result {
					r := checks.Fail(f("outside", map[string]string{"target": "s3://acme-backups", "place": "Ashburn, United States", "home": "Germany"}))
					r.Locations = []checks.Location{{Kind: "Backup", Name: "s3://acme-backups", Place: "Ashburn, United States", Country: "US", Confidence: "likely", Provider: "Amazon Web Services"}}
					return r
				}(),
				"outside-services": func() checks.Result {
					r := checks.Pass(map[string]string{"count": "3"})
					r.Locations = []checks.Location{
						{Kind: "Service", Name: "Stripe (payments)", Place: "United States", Country: "US", Confidence: "likely", Review: true},
						{Kind: "Service", Name: "Postmark (email)", Place: "United States", Country: "US", Confidence: "likely", Review: true},
						{Kind: "Service", Name: "Sentry (errors)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "likely", Review: true},
					}
					return r
				}(),
				"payment-data": checks.Pass(map[string]string{"count": "1", "home": "Germany"}),
			},
			pass: map[string]map[string]string{
				"load": {"load": "0.42"}, "memory": {"percent": "61", "total": "4 GB"}, "containers": {"count": "3"},
				"certificates": {"count": "2", "limit": "14"}, "backups": {"age": "5 hours", "opens": ", and it opens"},
				"open-ports": {"ports": "22, 80, 443"}, "firewall": {"firewall": "ufw"},
				"login-protection": {"protection": "fail2ban is running"}, "secrets-in-files": {"count": "38"},
			},
		},
		{
			name: "checkout-db-prod", os: "Ubuntu 24.04 LTS",
			results: map[string]checks.Result{
				"updates":          checks.Fail(f("waiting", map[string]string{"count": "3", "limit": "7"})),
				"containers":       checks.PassNone(),
				"risky-containers": checks.PassNone(),
				"server-location":  frankfurt("checkout-db-prod"),
				"database-connections": func() checks.Result {
					r := checks.Pass(map[string]string{"count": "1", "home": "Germany"})
					r.Locations = []checks.Location{{Kind: "Database", Name: "orders (this server)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed", Payment: true}}
					return r
				}(),
				"backup-destinations": func() checks.Result {
					r := checks.Pass(map[string]string{"count": "1", "home": "Germany"})
					r.Locations = []checks.Location{{Kind: "Backup", Name: "fra1.digitaloceanspaces.com/acme-db", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed", Provider: "DigitalOcean"}}
					return r
				}(),
				"outside-services": checks.PassNone(),
				"payment-data":     checks.Pass(map[string]string{"count": "1", "home": "Germany"}),
			},
			pass: map[string]map[string]string{
				"load": {"load": "0.35"}, "memory": {"percent": "47", "total": "8 GB"},
				"certificates": {"count": "1", "limit": "14"}, "backups": {"age": "3 hours", "opens": ", and it opens"},
				"open-ports": {"ports": "22"}, "firewall": {"firewall": "ufw"},
				"login-protection": {"protection": "SSH password login is off, so there is no password to guess"}, "secrets-in-files": {"count": "12"},
			},
		},
		{
			name: "storefront-web-prod", os: "Debian 12",
			results: map[string]checks.Result{
				"certificates": checks.Fail(f("expiring", map[string]string{"host": "shop.example.com", "days": "9"})),
				"server-location": func() checks.Result {
					r := checks.Fail(f("outside", map[string]string{"place": "Amsterdam, Netherlands", "home": "Germany"}))
					r.Locations = []checks.Location{place("Server", "storefront-web-prod", "Amsterdam, Netherlands", "NL", "DigitalOcean")}
					return r
				}(),
				"leftovers":            checks.Fail(f("docker-waste", map[string]string{"size": "4.2 GB"})),
				"database-connections": checks.PassNone(),
				"backup-destinations":  checks.PassNone(),
				"outside-services": func() checks.Result {
					r := checks.Pass(map[string]string{"count": "1"})
					r.Locations = []checks.Location{{Kind: "Service", Name: "Cloudflare (CDN)", Place: "Worldwide", Confidence: "likely", Review: true}}
					return r
				}(),
				"payment-data": checks.PassNone(),
				"backups":      checks.Pass(map[string]string{"age": "20 hours", "opens": ", and it opens"}),
			},
			pass: map[string]map[string]string{
				"load": {"load": "0.21"}, "memory": {"percent": "52", "total": "2 GB"}, "containers": {"count": "2"},
				"open-ports": {"ports": "22, 80, 443"}, "firewall": {"firewall": "ufw"},
				"login-protection": {"protection": "fail2ban is running"}, "secrets-in-files": {"count": "21"},
			},
		},
		{
			name: "worker-prod", os: "Ubuntu 22.04 LTS",
			results: map[string]checks.Result{
				"risky-containers": checks.Fail(
					f("privileged", map[string]string{"name": "image-resizer"}),
					f("docker-socket", map[string]string{"name": "watchtower"}),
				),
				"vulnerabilities":      checks.Fail(f("image", map[string]string{"count": "4", "image": "node:16-alpine"})),
				"server-location":      frankfurt("worker-prod"),
				"database-connections": checks.Pass(map[string]string{"count": "1", "home": "Germany"}),
				"backup-destinations":  checks.PassNone(),
				"outside-services":     checks.PassNone(),
				"payment-data":         checks.PassNone(),
				"backups":              checks.Fail(f("not-set", nil)),
			},
			pass: map[string]map[string]string{
				"load": {"load": "0.08"}, "memory": {"percent": "31", "total": "8 GB"}, "containers": {"count": "4"},
				"certificates": {"count": "0", "limit": "14"},
				"open-ports":   {"ports": "22"}, "firewall": {"firewall": "ufw"},
				"login-protection": {"protection": "SSH password login is off, so there is no password to guess"}, "secrets-in-files": {"count": "17"},
			},
		},
		{
			name: "staging-1", os: "Ubuntu 22.04 LTS",
			results: map[string]checks.Result{
				"leftovers": checks.Fail(
					f("dev-tool-public", map[string]string{"name": "adminer", "tool": "Adminer"}),
					f("git-folder", map[string]string{"path": "/var/www/html/.git"}),
					f("debug", map[string]string{"path": "/var/www/html/.env", "setting": "APP_DEBUG=true"}),
				),
				"oom":                  checks.Fail(f("killed-no-swap", map[string]string{"process": "node", "time": killed.Format("15:04 on Mon 2 Jan"), "total": "1 GB"})),
				"memory":               checks.Fail(f("no-swap", map[string]string{"total": "1 GB"})),
				"firewall":             checks.Fail(f("off", nil)),
				"server-location":      frankfurt("staging-1"),
				"database-connections": checks.Pass(map[string]string{"count": "1", "home": "Germany"}),
				"backup-destinations":  checks.PassNone(),
				"outside-services":     checks.PassNone(),
				"payment-data":         checks.PassNone(),
				"backups":              checks.Fail(f("not-set", nil)),
			},
			pass: map[string]map[string]string{
				"load": {"load": "0.64"}, "containers": {"count": "3"},
				"certificates":     {"count": "1", "limit": "14"},
				"open-ports":       {"ports": "22, 80, 443, 8080"},
				"login-protection": {"protection": "fail2ban is running"}, "secrets-in-files": {"count": "9"},
			},
		},
	}

	ids := []string{}
	for _, c := range checks.Default().All() {
		ids = append(ids, c.ID())
	}
	out := map[string]scan.Report{}
	for i, s := range servers {
		results := map[string]checks.Result{}
		for _, id := range ids {
			vars := s.pass[id]
			if vars == nil {
				vars = shared[id]
			}
			if r, ok := s.results[id]; ok {
				results[id] = r
			} else {
				results[id] = checks.Pass(vars)
			}
		}
		start := now.Add(-time.Duration(4+i*3) * time.Minute)
		host := scan.Host{Name: s.name, OS: s.os, Tested: true, Root: true}
		out[s.name] = scan.Build(pack, host, start, 5.2+float64(i), home, ids, results)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
