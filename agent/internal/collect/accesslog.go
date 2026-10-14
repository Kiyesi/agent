package collect

import (
	"encoding/json"
	"math"
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
}

// nginx's "combined" format, with anything after it: some setups add
// $request_time as a number or as rt=0.123.
var combined = regexp.MustCompile(`^\S+ \S+ \S+ \[[^\]]+\] "([A-Z]+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "[^"]*")?(.*)$`)
var requestTime = regexp.MustCompile(`(?:^|\s)(?:rt=|request_time=)?"?(\d+\.\d{1,6})"?(?:\s|$)`)

// ParseAccessLine reads one access log line, in nginx's combined format or
// Caddy's JSON, and reports whether it was a request.
func ParseAccessLine(line string) (Request, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var c struct {
			Msg     string `json:"msg"`
			Request *struct {
				Method string `json:"method"`
				URI    string `json:"uri"`
			} `json:"request"`
			Status   int      `json:"status"`
			Duration *float64 `json:"duration"`
		}
		if json.Unmarshal([]byte(line), &c) != nil || c.Request == nil || c.Status == 0 {
			return Request{}, false
		}
		r := Request{Method: c.Request.Method, Path: c.Request.URI, Status: c.Status, Ms: -1}
		if c.Duration != nil {
			r.Ms = *c.Duration * 1000
		}
		return r, true
	}
	m := combined.FindStringSubmatch(line)
	if m == nil {
		return Request{}, false
	}
	status, _ := strconv.Atoi(m[3])
	r := Request{Method: m[1], Path: m[2], Status: status, Ms: -1}
	if t := requestTime.FindStringSubmatch(m[4]); t != nil {
		if s, err := strconv.ParseFloat(t[1], 64); err == nil {
			r.Ms = s * 1000
		}
	}
	return r, true
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

// MaxEndpoints is how many endpoints are kept per minute; the rest are
// counted together as "other", so a scan of random paths cannot make
// thousands of series.
const MaxEndpoints = 100

// EndpointStats is one endpoint's requests in one minute.
type EndpointStats struct {
	Endpoint string   `json:"endpoint"`
	Requests int      `json:"requests"`
	Errors   int      `json:"errors"`
	AvgMs    *float64 `json:"avg_ms"`
	P95Ms    *float64 `json:"p95_ms"`
}

type endpointAcc struct {
	requests, errors int
	sum              float64
	times            []float64
}

// Requests adds up a minute of requests by endpoint.
type Requests struct{ by map[string]*endpointAcc }

func (r *Requests) Add(req Request) {
	if r.by == nil {
		r.by = map[string]*endpointAcc{}
	}
	ep := Endpoint(req.Method, req.Path)
	a := r.by[ep]
	if a == nil {
		a = &endpointAcc{}
		r.by[ep] = a
	}
	a.requests++
	if req.Status >= 500 {
		a.errors++
	}
	if req.Ms >= 0 {
		a.sum += req.Ms
		// Keep at most 2,000 times per endpoint; enough for a 95th percentile.
		if len(a.times) < 2000 {
			a.times = append(a.times, req.Ms)
		}
	}
}

func (a *endpointAcc) stats(name string) EndpointStats {
	s := EndpointStats{Endpoint: name, Requests: a.requests, Errors: a.errors}
	if n := len(a.times); n > 0 {
		avg := round1(a.sum / float64(n))
		sort.Float64s(a.times)
		p95 := round1(a.times[int(math.Ceil(0.95*float64(n)))-1])
		s.AvgMs, s.P95Ms = &avg, &p95
	}
	return s
}

// Stats returns the minute's endpoints, busiest first, at most MaxEndpoints
// of them, and empties the counts.
func (r *Requests) Stats() []EndpointStats {
	names := make([]string, 0, len(r.by))
	for n := range r.by {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := r.by[names[i]], r.by[names[j]]
		if a.requests != b.requests {
			return a.requests > b.requests
		}
		return names[i] < names[j]
	})
	var out []EndpointStats
	other := &endpointAcc{}
	for i, n := range names {
		a := r.by[n]
		if i < MaxEndpoints-1 || len(names) <= MaxEndpoints {
			out = append(out, a.stats(n))
			continue
		}
		other.requests += a.requests
		other.errors += a.errors
		other.sum += a.sum
		other.times = append(other.times, a.times...)
	}
	if other.requests > 0 {
		out = append(out, other.stats("other"))
	}
	r.by = nil
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
