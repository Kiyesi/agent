package collect

import (
	"encoding/json"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Request is one line of a web server's access log.
type Request struct {
	Method string
	Path   string
	Status int
	// Ms is how long it took, or -1 when the log does not say.
	Ms float64
	// Host is the site the request was for, such as "shop.example.com",
	// or "" when the line does not say.
	Host string
}

// nginx's "combined" format, with anything after it: some setups add
// $request_time as a number or as rt=0.123. The line may start with the
// site: "vhost_combined" starts with $host:$server_port, and a common
// custom format with $host alone. Either has one more field before the
// time than "combined", which is how the site is told from the address.
var combined = regexp.MustCompile(`^(?:(\S+) )?\S+ \S+ \S+ \[[^\]]+\] "([A-Z]+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "[^"]*")?(.*)$`)
var requestTime = regexp.MustCompile(`(?:^|\s)(?:rt=|request_time=)?"?(\d+\.\d{1,6})"?(?:\s|$)`)

// ParseAccessLine reads one access log line, in nginx's combined format
// (with or without the site in front) or Caddy's JSON, and reports whether
// it was a request.
func ParseAccessLine(line string) (Request, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var c struct {
			Msg     string `json:"msg"`
			Request *struct {
				Method string `json:"method"`
				URI    string `json:"uri"`
				Host   string `json:"host"`
			} `json:"request"`
			Status   int      `json:"status"`
			Duration *float64 `json:"duration"`
		}
		if json.Unmarshal([]byte(line), &c) != nil || c.Request == nil || c.Status == 0 {
			return Request{}, false
		}
		r := Request{Method: c.Request.Method, Path: c.Request.URI, Status: c.Status, Ms: -1, Host: Site(c.Request.Host)}
		if c.Duration != nil {
			r.Ms = *c.Duration * 1000
		}
		return r, true
	}
	m := combined.FindStringSubmatch(line)
	if m == nil {
		return Request{}, false
	}
	status, _ := strconv.Atoi(m[4])
	r := Request{Method: m[2], Path: m[3], Status: status, Ms: -1, Host: Site(m[1])}
	if t := requestTime.FindStringSubmatch(m[5]); t != nil {
		if s, err := strconv.ParseFloat(t[1], 64); err == nil {
			r.Ms = s * 1000
		}
	}
	return r, true
}

var siteName = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$`)

// Site turns a Host header or server name into the site it names: lower
// case, without a port or a final dot. A "www." in front is kept as
// written, so www.example.com and example.com stay two sites. An address
// such as 203.0.113.9, nginx's catch-all "_", "-" and anything else that is
// not a plain name give "", for a request to no site in particular.
func Site(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(h, "[") || strings.Count(h, ":") > 1 {
		// An IPv6 address, with or without a port.
		return ""
	}
	h, _, _ = strings.Cut(h, ":")
	h = strings.TrimSuffix(h, ".")
	if h == "" || h == "_" || len(h) > 253 || net.ParseIP(h) != nil || !siteName.MatchString(h) {
		return ""
	}
	return h
}

var (
	allDigits = regexp.MustCompile(`^\d+$`)
	uuidLike  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	longHex   = regexp.MustCompile(`[0-9a-fA-F]{12,}`)
	hasDigit  = regexp.MustCompile(`\d`)
)

// idLike says whether a path part names one record rather than a route:
// a number, a UUID, a long code or hash, or an email address.
func idLike(seg string) bool {
	switch {
	case allDigits.MatchString(seg), uuidLike.MatchString(seg), strings.Contains(seg, "@"):
		return true
	case longHex.MatchString(seg) && hasDigit.MatchString(seg):
		return true
	case len(seg) >= 20 && hasDigit.MatchString(seg):
		return true
	}
	return false
}

// Endpoint turns a request into the route it belongs to, such as
// "GET /api/users/:id". The query string is dropped, so no value in it is
// ever sent.
func Endpoint(method, rawPath string) string {
	p, _, _ := strings.Cut(rawPath, "?")
	p, _, _ = strings.Cut(p, "#")
	if !strings.HasPrefix(p, "/") {
		p = "/"
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	out := make([]string, 0, len(parts))
	for i, seg := range parts {
		if i >= 6 {
			out = append(out, "…")
			break
		}
		if idLike(seg) {
			seg = ":id"
		}
		out = append(out, seg)
	}
	ep := "/" + strings.Join(out, "/")
	if len(ep) > 120 {
		ep = ep[:120]
	}
	if method == "" {
		method = "GET"
	}
	return method + " " + ep
}

// The limits on one minute of requests, so a scan of random paths or of
// made-up Host headers cannot make thousands of series:
//
//   - MaxEndpoints endpoints are sent per site; the rest are counted
//     together as that site's "other".
//   - MaxSites sites are kept; requests to any more are counted under
//     no site ("").
//   - MaxHTTP entries are sent in all, which is what the service accepts.
//     When the sites together have more, the busiest are kept and the rest
//     go to their site's "other".
const (
	MaxEndpoints = 100
	MaxSites     = 50
	MaxHTTP      = 500
)

// What is held in memory during the minute, so the agent stays small
// however many paths it sees: at most this many endpoints per site and in
// all (later ones go straight to "other"), and this many request times in
// all, enough for every endpoint's 95th percentile.
const (
	maxHeldPerSite = 1000
	maxHeld        = 5000
	maxHeldTimes   = 200_000
	maxTimesEach   = 2000
)

// EndpointStats is one endpoint's requests in one minute.
type EndpointStats struct {
	Endpoint string `json:"endpoint"`
	// Site is the site the requests were for, left out when unknown.
	Site     string   `json:"site,omitempty"`
	Requests int      `json:"requests"`
	Errors   int      `json:"errors"`
	AvgMs    *float64 `json:"avg_ms"`
	P95Ms    *float64 `json:"p95_ms"`
}

type endpointAcc struct {
	requests, errors int
	// timed is how many requests said how long they took; sum adds them.
	timed int
	sum   float64
	times []float64
}

// add counts b's requests in a, for "other".
func (a *endpointAcc) add(b *endpointAcc) {
	a.requests += b.requests
	a.errors += b.errors
	a.timed += b.timed
	a.sum += b.sum
	a.times = append(a.times, b.times...)
}

type siteAcc struct {
	by    map[string]*endpointAcc
	other *endpointAcc
}

// Requests adds up a minute of requests by site and endpoint.
type Requests struct {
	sites map[string]*siteAcc
	// named counts the sites other than "", held the endpoints and times
	// the times kept.
	named, held, times int
}

func (r *Requests) Add(req Request) {
	if r.sites == nil {
		r.sites = map[string]*siteAcc{}
	}
	site := req.Host
	s := r.sites[site]
	if s == nil && site != "" && r.named >= MaxSites {
		site = ""
		s = r.sites[site]
	}
	if s == nil {
		s = &siteAcc{by: map[string]*endpointAcc{}}
		r.sites[site] = s
		if site != "" {
			r.named++
		}
	}
	ep := Endpoint(req.Method, req.Path)
	a := s.by[ep]
	if a == nil {
		if len(s.by) >= maxHeldPerSite || r.held >= maxHeld {
			if s.other == nil {
				s.other = &endpointAcc{}
			}
			a = s.other
		} else {
			a = &endpointAcc{}
			s.by[ep] = a
			r.held++
		}
	}
	a.requests++
	if req.Status >= 500 {
		a.errors++
	}
	if req.Ms >= 0 {
		a.timed++
		a.sum += req.Ms
		if len(a.times) < maxTimesEach && r.times < maxHeldTimes {
			a.times = append(a.times, req.Ms)
			r.times++
		}
	}
}

func (a *endpointAcc) stats(site, name string) EndpointStats {
	s := EndpointStats{Endpoint: name, Site: site, Requests: a.requests, Errors: a.errors}
	if a.timed > 0 {
		avg := round1(a.sum / float64(a.timed))
		s.AvgMs = &avg
	}
	if n := len(a.times); n > 0 {
		sort.Float64s(a.times)
		p95 := round1(a.times[int(math.Ceil(0.95*float64(n)))-1])
		s.P95Ms = &p95
	}
	return s
}

type namedAcc struct {
	site, name string
	acc        *endpointAcc
}

// busiest sorts the most requests first, then by site and name, so the
// order does not change from run to run.
func busiest(list []namedAcc) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.acc.requests != b.acc.requests {
			return a.acc.requests > b.acc.requests
		}
		if a.site != b.site {
			return a.site < b.site
		}
		return a.name < b.name
	})
}

// Stats returns the minute's endpoints, site by site with the busiest site
// first, and within each site the busiest endpoint first and "other" last,
// within the limits above. It empties the counts.
func (r *Requests) Stats() []EndpointStats {
	var kept []namedAcc
	others := map[string]*endpointAcc{}
	fold := func(site string, a *endpointAcc) {
		if others[site] == nil {
			others[site] = &endpointAcc{}
		}
		others[site].add(a)
	}
	for site, s := range r.sites {
		list := make([]namedAcc, 0, len(s.by))
		for n, a := range s.by {
			list = append(list, namedAcc{site, n, a})
		}
		busiest(list)
		keep := len(list)
		if keep > MaxEndpoints || (s.other != nil && keep >= MaxEndpoints) {
			keep = MaxEndpoints - 1
		}
		kept = append(kept, list[:keep]...)
		for _, e := range list[keep:] {
			fold(site, e.acc)
		}
		if s.other != nil {
			fold(site, s.other)
		}
	}
	if len(kept)+len(others) > MaxHTTP {
		// Room for one "other" per site, and the busiest endpoints in the rest.
		room := MaxHTTP - len(r.sites)
		busiest(kept)
		for _, e := range kept[room:] {
			fold(e.site, e.acc)
		}
		kept = kept[:room]
	}

	bySite := map[string][]namedAcc{}
	total := map[string]int{}
	for _, e := range kept {
		bySite[e.site] = append(bySite[e.site], e)
		total[e.site] += e.acc.requests
	}
	for site, a := range others {
		total[site] += a.requests
	}
	sites := make([]string, 0, len(total))
	for site := range total {
		sites = append(sites, site)
	}
	sort.Slice(sites, func(i, j int) bool {
		if total[sites[i]] != total[sites[j]] {
			return total[sites[i]] > total[sites[j]]
		}
		return sites[i] < sites[j]
	})
	var out []EndpointStats
	for _, site := range sites {
		list := bySite[site]
		busiest(list)
		for _, e := range list {
			out = append(out, e.acc.stats(site, e.name))
		}
		if a := others[site]; a != nil && a.requests > 0 {
			out = append(out, a.stats(site, "other"))
		}
	}
	*r = Requests{}
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
