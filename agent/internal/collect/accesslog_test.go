package collect

import (
	"fmt"
	"testing"
)

func TestParseAccessLine(t *testing.T) {
	cases := []struct {
		line string
		want Request
	}{
		{`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /api/users/42?token=abc HTTP/1.1" 200 512 "-" "curl/8"`,
			Request{"GET", "/api/users/42?token=abc", 200, -1}},
		{`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "POST /checkout HTTP/2.0" 502 0 "https://x" "Mozilla" 0.250`,
			Request{"POST", "/checkout", 502, 250}},
		{`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua" rt=0.012 uct="0.000"`,
			Request{"GET", "/", 200, 12}},
		{`{"level":"info","ts":1791500000.1,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/health","host":"api.kiyesi.dev"},"duration":0.0021,"size":11,"status":200}`,
			Request{"GET", "/health", 200, 2.1}},
	}
	for _, c := range cases {
		got, ok := ParseAccessLine(c.line)
		if !ok {
			t.Errorf("not read: %s", c.line)
			continue
		}
		if got.Method != c.want.Method || got.Path != c.want.Path || got.Status != c.want.Status || fmt.Sprintf("%.1f", got.Ms) != fmt.Sprintf("%.1f", c.want.Ms) {
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
