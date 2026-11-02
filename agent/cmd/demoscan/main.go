// Command demoscan prints the sample scans for the demo at demo.kiyesi.dev:
// five made-up servers, each with chosen results, put into words by the
// same pack and graded the same way as a real scan. Never shipped.
//
//	go run ./cmd/demoscan -now 2026-10-18T12:00:00Z > scans.json
//
// The servers sit in several countries with several providers, and no home
// country is chosen: the sample never puts one country at its centre.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

// The same on every server unless a server says otherwise.
var shared = map[string]map[string]string{
	"disk":    {"limit": "80"},
	"updates": {"limit": "7"},
}

type server struct {
	name, os string
	// The system as os-release names it, for the end-of-life check.
	osID, osVersion, osName string
	// results by check id; a check not listed here passes with pass[id].
	results map[string]checks.Result
	pass    map[string]map[string]string
}

func f(key string, vars map[string]string) checks.Finding { return checks.Found(key, vars) }

func place(kind, name, city, country, provider string) checks.Location {
	return checks.Location{Kind: kind, Name: name, Place: city, Country: country, Confidence: "confirmed", Provider: provider}
}

// noHome is a data-location check's pass with no home country chosen: it
// places things without comparing them with one country.
func noHome(vars map[string]string, locs ...checks.Location) checks.Result {
	r := checks.Pass(vars)
	r.NoHome = true
	r.Locations = locs
	return r
}

// located is the server-location check's pass for a server in city.
func located(name, city, country, provider string) checks.Result {
	return noHome(map[string]string{"place": city}, place("Server", name, city, country, provider))
}

// endOfLife judges the system's security fixes as the end-of-life check
// does (internal/checks/endoflife.go), from the same built-in dates, so the
// sample says what a real agent would on the day of the recording.
func endOfLife(table *packs.EndOfLife, s server, now time.Time) checks.Result {
	system, _, rel, ok := table.Lookup(s.osID, s.osVersion, s.osName)
	if !ok {
		return checks.Skip("unknown-release", map[string]string{"os": s.osName, "fetched": table.Fetched})
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	days := int(rel.Fixes.Sub(today).Hours() / 24)
	vars := map[string]string{"os": s.osName, "date": rel.Fixes.Format("2 Jan 2006")}
	variant := map[string]string{"ubuntu": "ubuntu", "debian": "debian"}[system]
	switch {
	case days < 0:
		return checks.Fail(checks.Finding{Key: "ended", Variant: variant, Vars: vars})
	case days <= 90:
		vars["days"] = strconv.Itoa(days)
		return checks.Fail(checks.Finding{Key: "ending", Variant: variant, Vars: vars})
	case !rel.Regular.IsZero() && today.After(rel.Regular):
		return checks.Fail(checks.Finding{Key: "lts", Variant: variant, Vars: vars})
	}
	vars["with"] = ""
	return checks.Pass(vars)
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
	eol, err := packs.LoadEndOfLife()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The memory kill on staging-1: the seed (api/src/testing/demo-seed.ts)
	// puts it at the same minute, from the same -now.
	killed := now.Add(-50 * time.Hour).Truncate(time.Minute)
	servers := []server{
		{
			name: "checkout-api-prod", os: "Ubuntu 24.04 LTS",
			osID: "ubuntu", osVersion: "24.04", osName: "Ubuntu 24.04.1 LTS",
			results: map[string]checks.Result{
				"exposed-databases": checks.Fail(f("open", map[string]string{"database": "Redis", "port": "6379", "service": "redis"})),
				"ssh":               checks.Fail(f("password", nil)),
				"server-location":   located("checkout-api-prod", "Frankfurt, Germany", "DE", "DigitalOcean"),
				"database-connections": noHome(map[string]string{"count": "2"},
					checks.Location{Kind: "Database", Name: "orders (checkout-db-prod)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed", Private: true, Payment: true, Host: "10.114.0.4"},
					checks.Location{Kind: "Database", Name: "redis (this server)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed"},
				),
				"backup-destinations": noHome(map[string]string{"count": "1"},
					checks.Location{Kind: "Backup", Name: "s3://acme-backups", Place: "Ashburn, United States", Country: "US", Confidence: "likely", Provider: "Amazon Web Services"},
				),
				"outside-services": func() checks.Result {
					r := checks.Pass(map[string]string{"count": "3"})
					r.Locations = []checks.Location{
						{Kind: "Service", Name: "Stripe (payments)", Place: "United States", Country: "US", Confidence: "likely", Review: true},
						{Kind: "Service", Name: "Postmark (email)", Place: "United States", Country: "US", Confidence: "likely", Review: true},
						{Kind: "Service", Name: "Sentry (errors)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "likely", Review: true},
					}
					return r
				}(),
				"payment-data": noHome(map[string]string{"count": "1"}),
			},
			pass: map[string]map[string]string{
				"load": {"load": "0.42"}, "memory": {"percent": "61", "total": "4 GB"}, "containers": {"count": "3"},
				"certificates": {"count": "2", "limit": "14"}, "backups": {"age": "5 hours", "opens": ", and it opens"},
				// Redis's port is judged by Exposed databases, as the agent says.
				"open-ports":       {"ports": "22, 80, 443", "databases": "; database port 6379 is judged under Exposed databases"},
				"firewall":         {"firewall": "ufw"},
				"login-protection": {"protection": "fail2ban is running"}, "secrets-in-files": {"count": "38"},
			},
		},
		{
			name: "checkout-db-prod", os: "Ubuntu 24.04 LTS",
			osID: "ubuntu", osVersion: "24.04", osName: "Ubuntu 24.04.1 LTS",
			results: map[string]checks.Result{
				"updates":          checks.Fail(f("waiting", map[string]string{"count": "3", "limit": "7"})),
				"containers":       checks.PassNone(),
				"risky-containers": checks.PassNone(),
				"server-location":  located("checkout-db-prod", "Frankfurt, Germany", "DE", "DigitalOcean"),
				"database-connections": noHome(map[string]string{"count": "1"},
					checks.Location{Kind: "Database", Name: "orders (this server)", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed", Payment: true},
				),
				"backup-destinations": noHome(map[string]string{"count": "1"},
					checks.Location{Kind: "Backup", Name: "fra1.digitaloceanspaces.com/acme-db", Place: "Frankfurt, Germany", Country: "DE", Confidence: "confirmed", Provider: "DigitalOcean"},
				),
				"outside-services": checks.PassNone(),
				"payment-data":     noHome(map[string]string{"count": "1"}),
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
			osID: "debian", osVersion: "12", osName: "Debian GNU/Linux 12 (bookworm)",
			results: map[string]checks.Result{
				"certificates":         checks.Fail(f("expiring", map[string]string{"host": "shop.example.com", "days": "9"})),
				"server-location":      located("storefront-web-prod", "Singapore", "SG", "Akamai (Linode)"),
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
			osID: "ubuntu", osVersion: "22.04", osName: "Ubuntu 22.04.5 LTS",
			results: map[string]checks.Result{
				"risky-containers": checks.Fail(
					f("privileged", map[string]string{"name": "image-resizer"}),
					f("docker-socket", map[string]string{"name": "watchtower"}),
				),
				"vulnerabilities":      checks.Fail(f("image", map[string]string{"count": "4", "image": "node:16-alpine"})),
				"server-location":      located("worker-prod", "Helsinki, Finland", "FI", "Hetzner"),
				"database-connections": noHome(map[string]string{"count": "1"}),
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
			osID: "ubuntu", osVersion: "22.04", osName: "Ubuntu 22.04.5 LTS",
			results: map[string]checks.Result{
				"leftovers": checks.Fail(
					f("dev-tool-public", map[string]string{"name": "adminer", "tool": "Adminer"}),
					f("git-folder", map[string]string{"path": "/var/www/html/.git"}),
					f("debug", map[string]string{"path": "/var/www/html/.env", "setting": "APP_DEBUG=true"}),
				),
				"oom":                  checks.Fail(f("killed-no-swap", map[string]string{"process": "node", "time": killed.Format("15:04 on Mon 2 Jan"), "total": "1 GB"})),
				"memory":               checks.Fail(f("no-swap", map[string]string{"total": "1 GB"})),
				"firewall":             checks.Fail(f("off", map[string]string{"ssh_port": "22"})),
				"server-location":      located("staging-1", "Toronto, Canada", "CA", "DigitalOcean"),
				"database-connections": noHome(map[string]string{"count": "1"}),
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
		results := map[string]checks.Result{"end-of-life": endOfLife(eol, s, now)}
		for _, id := range ids {
			vars := s.pass[id]
			if vars == nil {
				vars = shared[id]
			}
			if r, ok := s.results[id]; ok {
				results[id] = r
			} else if _, ok := results[id]; !ok {
				results[id] = checks.Pass(vars)
			}
		}
		start := now.Add(-time.Duration(4+i*3) * time.Minute)
		host := scan.Host{Name: s.name, OS: s.os, Tested: true, Root: true}
		out[s.name] = scan.Build(pack, host, start, 5.2+float64(i), "", ids, results)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
