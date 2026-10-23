package guard

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Probe reads what works now. Tests replace each part.
type Probe struct {
	// Failed lists the services systemd says failed.
	Failed func(ctx context.Context) []string
	// Containers lists the running containers' names.
	Containers func(ctx context.Context) []string
	// Get answers an address's status code, or 0 when nothing answered.
	Get func(ctx context.Context, address string) int
}

// Read notes the services, containers and sites now.
func (p Probe) Read(ctx context.Context, sites []string) State {
	st := State{Sites: map[string]int{}}
	if p.Failed != nil {
		st.Failed = sorted(p.Failed(ctx))
	}
	if p.Containers != nil {
		st.Containers = sorted(p.Containers(ctx))
	}
	for _, s := range sites {
		if p.Get != nil {
			st.Sites[s] = p.Get(ctx, s)
		}
	}
	return st
}

func sorted(list []string) []string {
	out := append([]string{}, list...)
	sort.Strings(out)
	return out
}

// ParseFailed reads systemctl --failed --plain --no-legend: one unit per line.
func ParseFailed(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.Contains(f[0], ".") {
			units = append(units, f[0])
		}
	}
	return units
}

// SiteGetter asks an address with a short wait and no redirects followed.
// Only this server's own addresses are asked, so a certificate made for a
// name is not held against an address like 127.0.0.1.
func SiteGetter() func(ctx context.Context, address string) int {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: nil,
			// #nosec G402 -- only the server's own addresses are asked, and only whether they answer.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	return func(ctx context.Context, address string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return 0
		}
		req.Header.Set("User-Agent", "kiyesi-guard")
		res, err := client.Do(req)
		if err != nil {
			return 0
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
}

// LocalSite says whether an address may be asked: only this server's own.
func LocalSite(address string) error {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an address like http://127.0.0.1:3000/health", address)
	}
	switch h := u.Hostname(); h {
	case "127.0.0.1", "localhost", "::1":
		return nil
	default:
		return fmt.Errorf("%s is not this server: guard asks only 127.0.0.1 or localhost", h)
	}
}

// DefaultSites are the web server's own addresses when it listens on 80 or 443.
func DefaultSites(ports []int) []string {
	var out []string
	for _, p := range ports {
		switch p {
		case 80:
			out = append(out, "http://127.0.0.1/")
		case 443:
			out = append(out, "https://127.0.0.1/")
		}
	}
	return out
}

// Worse is what broke between before and after, in words, worst first.
func Worse(before, after State) []string {
	var out []string
	was := map[string]bool{}
	for _, u := range before.Failed {
		was[u] = true
	}
	for _, u := range after.Failed {
		if !was[u] {
			out = append(out, u+" failed")
		}
	}
	running := map[string]bool{}
	for _, c := range after.Containers {
		running[c] = true
	}
	for _, c := range before.Containers {
		if !running[c] {
			out = append(out, "container "+c+" stopped")
		}
	}
	sites := make([]string, 0, len(before.Sites))
	for s := range before.Sites {
		sites = append(sites, s)
	}
	sort.Strings(sites)
	for _, s := range sites {
		b, a := before.Sites[s], after.Sites[s]
		if b > 0 && b < 500 && (a == 0 || a >= 500) {
			if a == 0 {
				out = append(out, fmt.Sprintf("%s does not answer (before: %d)", s, b))
			} else {
				out = append(out, fmt.Sprintf("%s answers %d (before: %d)", s, a, b))
			}
		}
	}
	if after.Score < before.Score && after.Letter != "" && before.Letter != "" {
		out = append(out, fmt.Sprintf("the grade fell from %s %d to %s %d", before.Letter, before.Score, after.Letter, after.Score))
	}
	return out
}

// PackageChange is one package the command installed, removed or changed.
type PackageChange struct {
	Name, Before, After string
}

// PackageChanges compares "name version" lists.
func PackageChanges(before, after []string) []PackageChange {
	split := func(list []string) map[string]string {
		m := map[string]string{}
		for _, l := range list {
			n, v, _ := strings.Cut(l, " ")
			m[n] = v
		}
		return m
	}
	b, a := split(before), split(after)
	var out []PackageChange
	for n, v := range a {
		if b[n] != v {
			out = append(out, PackageChange{Name: n, Before: b[n], After: v})
		}
	}
	for n, v := range b {
		if _, ok := a[n]; !ok {
			out = append(out, PackageChange{Name: n, Before: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// BackCommand is how to go back to the version before, when apt still
// has it; it is printed, never run.
func BackCommand(c PackageChange) string {
	switch {
	case c.Before == "":
		return "sudo apt-get remove " + c.Name
	case c.After == "":
		return "sudo apt-get install " + c.Name + "=" + c.Before
	default:
		return "sudo apt-get install --allow-downgrades " + c.Name + "=" + c.Before
	}
}
