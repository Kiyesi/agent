package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

// mcpAPI answers like the service, and keeps every request it was sent.
func mcpAPI(t *testing.T, allowed bool) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var mu sync.Mutex
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		mu.Unlock()
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"ai_not_allowed","message":"Your team has not allowed AI assistants to read Kiyesi. An owner can allow it in the dashboard: Team and security, AI assistants."}`))
			return
		}
		switch r.URL.Path {
		case "/v1/servers":
			_, _ = w.Write([]byte(`{"servers":[{"id":"s1","name":"shop-prod","status":"ok","lastScan":{"grade":{"score":70,"letter":"C"}}}]}`))
		case "/v1/servers/s1":
			_, _ = w.Write([]byte(`{"server":{"id":"s1","name":"shop-prod"},"report":{"checks":[{"id":"ssh","findings":[{"sentence":"SSH allows password login","fix":"sudo kiyesi fix ssh-password"}]}]}}`))
		case "/v1/servers/s1/metrics":
			_, _ = w.Write([]byte(`{"step":60,"cpu":[[1,10],[2,30],[3,20]],"memory":[[1,50]],"disk":{"/":[[1,70],[2,71]]},"requests":[],"errors":[],"p95":[],"deploys":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","message":"Not found."}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// converse sends the lines as an assistant would and returns each answer.
func converse(t *testing.T, c *api.Client, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := serveMCP(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, c); err != nil {
		t.Fatal(err)
	}
	var answers []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		answers = append(answers, m)
	}
	return answers
}

func textOf(t *testing.T, answer map[string]any) (string, bool) {
	t.Helper()
	r, _ := answer["result"].(map[string]any)
	content, _ := r["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("answer = %v", answer)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	isErr, _ := r["isError"].(bool)
	return text, isErr
}

func TestMCPAnswersAnAssistantReadOnly(t *testing.T) {
	srv, seen := mcpAPI(t, true)
	c := api.New(srv.URL, "kli_test")
	c.Via = "mcp"
	got := converse(t, c,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"servers","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"server","arguments":{"name":"shop-prod"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"metrics","arguments":{"name":"shop-prod","range":"1h"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"server","arguments":{"name":"nope"}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_server","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":9,"method":"resources/list"}`,
	)
	// The notification gets no answer: 9 answers for 10 lines.
	if len(got) != 9 {
		t.Fatalf("answers = %v", got)
	}
	init, _ := got[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" {
		t.Errorf("version = %v", init["protocolVersion"])
	}
	tools, _ := got[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 10 {
		t.Errorf("tools = %d", len(tools))
	}
	for _, x := range tools {
		tool := x.(map[string]any)
		if tool["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Errorf("%v is not marked read-only", tool["name"])
		}
	}
	if text, isErr := textOf(t, got[2]); isErr || !strings.Contains(text, `"name":"shop-prod"`) {
		t.Errorf("servers: %s", text)
	}
	if text, _ := textOf(t, got[3]); !strings.Contains(text, "sudo kiyesi fix ssh-password") {
		t.Errorf("server: %s", text)
	}
	text, _ := textOf(t, got[4])
	var m map[string]any
	_ = json.Unmarshal([]byte(text), &m)
	cpu, _ := m["cpu_percent"].(map[string]any)
	if cpu["highest"] != 30.0 || cpu["average"] != 20.0 || cpu["latest"] != 20.0 {
		t.Errorf("metrics summed up = %s", text)
	}
	if text, isErr := textOf(t, got[5]); !isErr || !strings.Contains(text, `no server called "nope"`) {
		t.Errorf("unknown server: %s", text)
	}
	if text, isErr := textOf(t, got[6]); !isErr || !strings.Contains(text, "no tool called") {
		t.Errorf("unknown tool: %s", text)
	}
	if e, _ := got[8]["error"].(map[string]any); e["code"] != -32601.0 {
		t.Errorf("unknown method: %v", got[8])
	}
	// Every request was a read, and said it came from an AI assistant.
	for _, r := range *seen {
		if r.Method != http.MethodGet || r.Header.Get("X-Kiyesi-Client") != "mcp" {
			t.Errorf("%s %s with client %q", r.Method, r.URL.Path, r.Header.Get("X-Kiyesi-Client"))
		}
	}
}

func TestMCPSaysWhenTheTeamHasNotAllowedIt(t *testing.T) {
	srv, _ := mcpAPI(t, false)
	c := api.New(srv.URL, "kli_test")
	c.Via = "mcp"
	got := converse(t, c, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"alerts","arguments":{}}}`)
	text, isErr := textOf(t, got[0])
	if !isErr || !strings.Contains(text, "An owner can allow it in the dashboard") {
		t.Errorf("%v %s", isErr, text)
	}
}

func TestMCPRejectsBadInput(t *testing.T) {
	srv, _ := mcpAPI(t, true)
	c := api.New(srv.URL, "kli_test")
	got := converse(t, c, `not json`, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"logs","arguments":{"range":"forever"}}}`)
	if e, _ := got[0]["error"].(map[string]any); e["code"] != -32700.0 {
		t.Errorf("not json: %v", got[0])
	}
	if text, isErr := textOf(t, got[1]); !isErr || !strings.Contains(text, `"forever" is not one of`) {
		t.Errorf("bad range: %s", text)
	}
	// The service keeps error and warn only: info is not offered, and refused here.
	got = converse(t, c, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"logs","arguments":{"level":"info"}}}`)
	if text, isErr := textOf(t, got[0]); !isErr || !strings.Contains(text, `"info" is not one of error, warning`) {
		t.Errorf("info level: %s", text)
	}
	got = converse(t, c, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)
	if list, _ := json.Marshal(got[0]); strings.Contains(string(list), `"info"`) {
		t.Errorf("the logs tool must not offer info: %s", list)
	}
}
