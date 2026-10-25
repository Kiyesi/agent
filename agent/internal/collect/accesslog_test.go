package collect

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestParseAccessLine(t *testing.T) {
	cases := []struct {
		line string
		want Request
	}{
		{`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /api/users/42?token=abc HTTP/1.1" 200 512 "-" "curl/8"`,
			Request{"GET", "/api/users/42?token=abc", 200, -1, ""}},
		{`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "POST /checkout HTTP/2.0" 502 0 "https://x" "Mozilla" 0.250`,
			Request{"POST", "/checkout", 502, 250, ""}},
		{`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua" rt=0.012 uct="0.000"`,
			Request{"GET", "/", 200, 12, ""}},
		// A user name in the combined format is not a site.
		{`203.0.113.9 - ada [10/Oct/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 200 5 "-" "ua"`,
			Request{"GET", "/admin", 200, -1, ""}},
		{`{"level":"info","ts":1791500000.1,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/health","host":"api.kiyesi.dev"},"duration":0.0021,"size":11,"status":200}`,
			Request{"GET", "/health", 200, 2.1, "api.kiyesi.dev"}},
		// Caddy with a port and capitals in the Host header.
		{`{"msg":"handled request","request":{"method":"POST","uri":"/pay","host":"Shop.Example.com:8443"},"duration":0.1,"status":201}`,
			Request{"POST", "/pay", 201, 100, "shop.example.com"}},
		// Caddy reached by address names no site.
		{`{"msg":"handled request","request":{"method":"GET","uri":"/","host":"203.0.113.9:80"},"status":200}`,
			Request{"GET", "/", 200, -1, ""}},
		// nginx's vhost_combined: $host:$server_port first.
		{`shop.example.com:443 203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "ua"`,
			Request{"GET", "/health", 200, -1, "shop.example.com"}},
		{`www.example.com:80 203.0.113.9 - ada [10/Oct/2026:10:00:00 +0000] "GET /cart HTTP/1.1" 500 2 "-" "ua" 0.031`,
			Request{"GET", "/cart", 500, 31, "www.example.com"}},
		// A custom format with $host alone first, and an IPv6 address.
		{`api.example.com 2001:db8::1 - - [10/Oct/2026:10:00:00 +0000] "DELETE /items/9 HTTP/2.0" 204 0 "-" "ua" rt=0.004`,
			Request{"DELETE", "/items/9", 204, 4, "api.example.com"}},
		// Requests with no Host header, or by address, name no site.
		{`_ 203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET / HTTP/1.0" 400 0 "-" "-"`,
			Request{"GET", "/", 400, -1, ""}},
		{`198.51.100.4:80 203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "-"`,
			Request{"GET", "/.env", 404, -1, ""}},
	}
	for _, c := range cases {
		got, ok := ParseAccessLine(c.line)
		if !ok {
			t.Errorf("not read: %s", c.line)
			continue
		}
		if got.Method != c.want.Method || got.Path != c.want.Path || got.Status != c.want.Status || got.Host != c.want.Host || fmt.Sprintf("%.1f", got.Ms) != fmt.Sprintf("%.1f", c.want.Ms) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.line, got, c.want)
		}
	}
	for _, junk := range []string{"", "nginx started", `{"msg":"server running"}`} {
		if _, ok := ParseAccessLine(junk); ok {
			t.Errorf("read a non-request line as a request: %q", junk)
		}
	}
}

func TestEndpointHidesIdsAndQueryStrings(t *testing.T) {
	cases := map[string]string{
		"/api/users/42?token=secret":                         "GET /api/users/:id",
		"/orders/0f8b8c3e-6f5d-4b7a-9c1e-2d3f4a5b6c7d/items": "GET /orders/:id/items",
		"/reset/ZXhhbXBsZS1yZXNldC10b2tlbi12YWx1ZQ123":       "GET /reset/:id",
		"/_next/static/chunks/main.3fa2b1c9d0e1.js":          "GET /_next/static/chunks/:id",
		"/users/ada@example.com":                             "GET /users/:id",
		"/":                                                  "GET /",
		"/a/b/c/d/e/f/g/h":                                   "GET /a/b/c/d/e/f/…",
	}
	for path, want := range cases {
		if got := Endpoint("GET", path); got != want {
			t.Errorf("Endpoint(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestRequestsCountsErrorsAndTimes(t *testing.T) {
	var r Requests
	for i := 1; i <= 20; i++ {
		status := 200
		if i == 20 {
			status = 503
		}
		r.Add(Request{Method: "GET", Path: fmt.Sprintf("/api/items/%d", i), Status: status, Ms: float64(i * 10)})
	}
	r.Add(Request{Method: "GET", Path: "/health", Status: 200, Ms: -1})
	s := r.Stats()
	if len(s) != 2 || s[0].Endpoint != "GET /api/items/:id" || s[0].Requests != 20 || s[0].Errors != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if *s[0].P95Ms != 190 || *s[0].AvgMs != 105 {
		t.Errorf("p95 %v avg %v, want 190 and 105", *s[0].P95Ms, *s[0].AvgMs)
	}
	if s[1].AvgMs != nil || s[1].P95Ms != nil {
		t.Errorf("an endpoint with no times must send none: %+v", s[1])
	}
	if len(r.Stats()) != 0 {
		t.Error("Stats must empty the counts")
	}
}

func TestRequestsCapsEndpoints(t *testing.T) {
	var r Requests
	for i := 0; i < 500; i++ {
		r.Add(Request{Method: "GET", Path: fmt.Sprintf("/page-%c%c", 'a'+i%26, 'a'+i/26), Status: 200, Ms: 1})
	}
	s := r.Stats()
	if len(s) != MaxEndpoints || s[len(s)-1].Endpoint != "other" || s[len(s)-1].Requests != 500-(MaxEndpoints-1) {
		t.Errorf("got %d endpoints, last %+v", len(s), s[len(s)-1])
	}
}

func TestSiteNamesOneSite(t *testing.T) {
	cases := map[string]string{
		"Shop.Example.com":     "shop.example.com",
		"shop.example.com:443": "shop.example.com",
		"shop.example.com.":    "shop.example.com",
		"www.example.com":      "www.example.com",
		"localhost:3000":       "localhost",
		"":                     "",
		"-":                    "",
		"_":                    "",
		"203.0.113.9":          "",
		"203.0.113.9:8080":     "",
		"[2001:db8::1]:443":    "",
		"2001:db8::1":          "",
		"bad host":             "",
		"evil.example.com/x":   "",
		"a\"b":                 "",
	}
	for in, want := range cases {
		if got := Site(in); got != want {
			t.Errorf("Site(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequestsKeepsTwoSitesApart(t *testing.T) {
	var r Requests
	for i := 0; i < 3; i++ {
		r.Add(Request{Method: "GET", Path: "/health", Status: 200, Ms: 10, Host: "shop.example.com"})
	}
	r.Add(Request{Method: "GET", Path: "/health", Status: 503, Ms: 30, Host: "api.example.com"})
	r.Add(Request{Method: "GET", Path: "/health", Status: 200, Ms: -1})
	got := map[string]EndpointStats{}
	for _, s := range r.Stats() {
		got[s.Site+" "+s.Endpoint] = s
	}
	if len(got) != 3 {
		t.Fatalf("stats = %+v", got)
	}
	if s := got["shop.example.com GET /health"]; s.Requests != 3 || s.Errors != 0 || *s.AvgMs != 10 {
		t.Errorf("shop: %+v", s)
	}
	if s := got["api.example.com GET /health"]; s.Requests != 1 || s.Errors != 1 || *s.P95Ms != 30 {
		t.Errorf("api: %+v", s)
	}
	if s := got[" GET /health"]; s.Requests != 1 || s.AvgMs != nil {
		t.Errorf("no site: %+v", s)
	}
}

func TestRequestsOrdersSitesBusiestFirst(t *testing.T) {
	var r Requests
	r.Add(Request{Method: "GET", Path: "/a", Status: 200, Ms: -1, Host: "quiet.example.com"})
	for i := 0; i < 5; i++ {
		r.Add(Request{Method: "GET", Path: fmt.Sprintf("/p%c", 'a'+i), Status: 200, Ms: -1, Host: "busy.example.com"})
	}
	r.Add(Request{Method: "GET", Path: "/pa", Status: 200, Ms: -1, Host: "busy.example.com"})
	s := r.Stats()
	if len(s) != 6 || s[0].Site != "busy.example.com" || s[0].Endpoint != "GET /pa" || s[0].Requests != 2 || s[5].Site != "quiet.example.com" {
		t.Errorf("stats = %+v", s)
	}
}

func TestRequestsCapsEndpointsPerSite(t *testing.T) {
	var r Requests
	for _, site := range []string{"a.example.com", "b.example.com"} {
		for i := 0; i < 150; i++ {
			r.Add(Request{Method: "GET", Path: fmt.Sprintf("/page-%d-x", i), Status: 200, Ms: 1, Host: site})
		}
	}
	r.Add(Request{Method: "GET", Path: "/only", Status: 200, Ms: 1, Host: "c.example.com"})
	per := map[string][]EndpointStats{}
	for _, s := range r.Stats() {
		per[s.Site] = append(per[s.Site], s)
	}
	for _, site := range []string{"a.example.com", "b.example.com"} {
		s := per[site]
		if len(s) != MaxEndpoints || s[len(s)-1].Endpoint != "other" || s[len(s)-1].Requests != 150-(MaxEndpoints-1) {
			t.Errorf("%s: %d endpoints, last %+v", site, len(s), s[len(s)-1])
		}
	}
	if len(per["c.example.com"]) != 1 || per["c.example.com"][0].Endpoint != "GET /only" {
		t.Errorf("c: %+v", per["c.example.com"])
	}
}

func TestRequestsCapsSites(t *testing.T) {
	var r Requests
	for i := 0; i < MaxSites+10; i++ {
		r.Add(Request{Method: "GET", Path: "/", Status: 200, Ms: -1, Host: fmt.Sprintf("site%d.example.com", i)})
	}
	r.Add(Request{Method: "GET", Path: "/", Status: 200, Ms: -1, Host: "site0.example.com"})
	sites := map[string]int{}
	for _, s := range r.Stats() {
		sites[s.Site] += s.Requests
	}
	if len(sites) != MaxSites+1 || sites[""] != 10 || sites["site0.example.com"] != 2 {
		t.Errorf("got %d sites, %d requests under no site: %v", len(sites), sites[""], sites)
	}
}

func TestRequestsCapsEntriesInAll(t *testing.T) {
	var r Requests
	sent := 0
	// 10 sites of 80 endpoints each is 800 entries, more than MaxHTTP.
	// Site i's endpoint j has i+j+1 requests.
	for i := 0; i < 10; i++ {
		for j := 0; j < 80; j++ {
			for k := 0; k <= i+j; k++ {
				r.Add(Request{Method: "GET", Path: fmt.Sprintf("/e%d-x", j), Status: 200, Ms: 1, Host: fmt.Sprintf("s%d.example.com", i)})
				sent++
			}
		}
	}
	s := r.Stats()
	if len(s) > MaxHTTP {
		t.Fatalf("%d entries, want at most %d", len(s), MaxHTTP)
	}
	total, least := 0, 1<<30
	kept := map[string]bool{}
	others := map[string]int{}
	for i, e := range s {
		total += e.Requests
		if e.Endpoint == "other" {
			others[e.Site]++
			if i+1 < len(s) && s[i+1].Site == e.Site {
				t.Errorf("other must come last in its site: %+v", s[i+1])
			}
			continue
		}
		kept[e.Site+" "+e.Endpoint] = true
		least = min(least, e.Requests)
	}
	if total != sent {
		t.Errorf("counted %d requests, want %d", total, sent)
	}
	if len(others) == 0 {
		t.Error("nothing was folded")
	}
	for site, n := range others {
		if n != 1 {
			t.Errorf("%s has %d others", site, n)
		}
	}
	// No endpoint folded into "other" is busier than the quietest kept.
	for i := 0; i < 10; i++ {
		for j := 0; j < 80; j++ {
			key := fmt.Sprintf("s%d.example.com GET /e%d-x", i, j)
			if !kept[key] && i+j+1 > least {
				t.Errorf("%s (%d requests) folded while one of %d was kept", key, i+j+1, least)
			}
		}
	}
}

func TestRequestsBoundsWhatItHolds(t *testing.T) {
	var r Requests
	for i := 0; i < maxHeldPerSite+500; i++ {
		r.Add(Request{Method: "GET", Path: fmt.Sprintf("/page-%d-x", i), Status: 200, Ms: 1, Host: "a.example.com"})
	}
	// One endpoint asked more often than the times kept for it.
	for i := 0; i < maxTimesEach+1000; i++ {
		ms := 10.0
		if i%2 == 1 {
			ms = 30
		}
		r.Add(Request{Method: "GET", Path: "/busy", Status: 200, Ms: ms, Host: "b.example.com"})
	}
	if len(r.sites["a.example.com"].by) != maxHeldPerSite || r.held > maxHeld || r.times > maxHeldTimes {
		t.Fatalf("held %d endpoints for a, %d in all, %d times", len(r.sites["a.example.com"].by), r.held, r.times)
	}
	if n := len(r.sites["b.example.com"].by["GET /busy"].times); n != maxTimesEach {
		t.Errorf("kept %d times for one endpoint", n)
	}
	total := 0
	for _, e := range r.Stats() {
		total += e.Requests
		if e.Endpoint == "GET /busy" && *e.AvgMs != 20 {
			t.Errorf("average %v, want 20 over every request", *e.AvgMs)
		}
	}
	if total != maxHeldPerSite+500+maxTimesEach+1000 {
		t.Errorf("counted %d requests", total)
	}
}

func TestEndpointStatsSendsTheSiteOnlyWhenKnown(t *testing.T) {
	avg := 1.5
	with, _ := json.Marshal(EndpointStats{Endpoint: "GET /health", Site: "shop.example.com", Requests: 2, AvgMs: &avg, P95Ms: &avg})
	if string(with) != `{"endpoint":"GET /health","site":"shop.example.com","requests":2,"errors":0,"avg_ms":1.5,"p95_ms":1.5}` {
		t.Errorf("with a site: %s", with)
	}
	without, _ := json.Marshal(EndpointStats{Endpoint: "GET /health", Requests: 2})
	if string(without) != `{"endpoint":"GET /health","requests":2,"errors":0,"avg_ms":null,"p95_ms":null}` {
		t.Errorf("without a site: %s", without)
	}
}

// Lines as Caddy wrote them on Kiyesi's own server: scanners asking it to
// pass traffic on (CONNECT), old domains still pointed at its address that
// it only redirects to https://, and the one site it serves. Only that one
// is a site; the rest are still counted, under no site.
func TestOnlyNamesTheServerAnswersAreSites(t *testing.T) {
	lines := []string{
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"35.231.112.57","proto":"HTTP/1.1","method":"CONNECT","host":"api.ipify.org:443","uri":"api.ipify.org:443"},"duration":0.0001,"size":0,"status":308}`,
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"172.70.1.2","proto":"HTTP/1.1","method":"GET","host":"casinoprospin.us","uri":"/"},"duration":0.0001,"size":0,"status":308}`,
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"172.70.1.3","proto":"HTTP/1.1","method":"GET","host":"britbetsonline.uk","uri":"/wp-login.php"},"duration":0.0001,"size":0,"status":308}`,
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"105.112.1.1","proto":"HTTP/2.0","method":"GET","host":"api.kiyesi.dev","uri":"/health"},"duration":0.004,"size":11,"status":200}`,
		`{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"105.112.1.1","proto":"HTTP/1.1","method":"GET","host":"api.kiyesi.dev","uri":"/"},"duration":0.0001,"size":0,"status":308}`,
	}
	if r, _ := ParseAccessLine(lines[0]); r.Host != "" {
		t.Errorf("a CONNECT named the site %q", r.Host)
	}
	var reqs Requests
	for _, l := range lines {
		r, ok := ParseAccessLine(l)
		if !ok {
			t.Fatalf("not read: %s", l)
		}
		reqs.Add(r)
	}
	sites := map[string]int{}
	total := 0
	for _, e := range reqs.Stats() {
		sites[e.Site] += e.Requests
		total += e.Requests
	}
	if len(sites) != 2 || sites["api.kiyesi.dev"] != 2 || sites[""] != 3 || total != len(lines) {
		t.Errorf("sites = %v, %d requests", sites, total)
	}
}

// nginx's own way to turn a name away, and a real site's temporary
// redirect, which is an answer.
func TestRefusalsAndTemporaryRedirects(t *testing.T) {
	var reqs Requests
	for _, l := range []string{
		`old-domain.example 203.0.113.9 - - [24/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 444 0 "-" "bot"`,
		`app.example.com 203.0.113.9 - - [24/Oct/2026:10:00:01 +0000] "GET /dashboard HTTP/1.1" 302 0 "-" "Mozilla"`,
	} {
		r, ok := ParseAccessLine(l)
		if !ok {
			t.Fatalf("not read: %s", l)
		}
		reqs.Add(r)
	}
	sites := map[string]bool{}
	for _, e := range reqs.Stats() {
		sites[e.Site] = true
	}
	if !sites["app.example.com"] || sites["old-domain.example"] {
		t.Errorf("sites = %v", sites)
	}
}
