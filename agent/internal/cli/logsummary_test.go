package cli

import "testing"

// The same cases as dashboard/src/lib/log-line.test.ts, so both say it alike.
func TestSummarize(t *testing.T) {
	for line, want := range map[string]string{
		`{"level":"info","logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"197.210.29.217","method":"GET","uri":"/v1/logs?range=1h&q=secret","headers":{"Cookie":["REDACTED"]}},"duration":0.012345,"status":200}`: "GET /v1/logs → 200 · 12 ms · 197.210.29.217",
		`{"level":"error","logger":"http.log.error.log0","msg":"dial tcp 172.18.0.6:8080: connect: connection refused","request":{"method":"GET","uri":"/health"},"status":502}`:                                                                                        "502 GET /health: dial tcp 172.18.0.6:8080: connect: connection refused",
		`{"level":30,"res":{"statusCode":202},"responseTime":53.06,"msg":"request completed"}`:                                                                                                                                                                          "request completed · 202 · 53 ms",
		`{"level":30,"req":{"method":"POST","url":"/v1/agent/batches?x=1"},"msg":"incoming request"}`:                                                                                                                                                                   "incoming request · POST /v1/agent/batches",
		`{"level":50,"msg":"request failed","err":{"message":"the log store answered 503"}}`:                                                                                                                                                                            "request failed: the log store answered 503",
		`FATAL ERROR: Reached heap limit`: "",
		`{not json}`:                      "",
		`{"a":1}`:                         "",
	} {
		if got := summarize(line); got != want {
			t.Errorf("summarize(%s)\n got %q\nwant %q", line, got, want)
		}
	}
}
