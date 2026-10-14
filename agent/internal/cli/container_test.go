package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestContainerModeNeedsAToken(t *testing.T) {
	t.Setenv("KIYESI_TOKEN", "")
	code, _, errOut := runCLI(t, "agent", "--container")
	if code != ExitUsage || !strings.Contains(errOut, "KIYESI_TOKEN") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

// Beside a managed service: it says it runs, then sends heartbeats with no
// scan and no host figures, from the address and token in the environment.
func TestContainerModeConnectsAndSendsHeartbeatsOnly(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var kinds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/v1/agent/connect" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["os"] != "container" {
				t.Errorf("connect said os %q", body["os"])
			}
			_, _ = w.Write([]byte(`{"server_id":"6ac8e2ce48aa8a76695e6a48"}`))
			return
		}
		var rd io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			rd, _ = gzip.NewReader(r.Body)
		}
		var b struct {
			Items []struct {
				Kind string `json:"kind"`
			} `json:"items"`
		}
		_ = json.NewDecoder(rd).Decode(&b)
		mu.Lock()
		for _, it := range b.Items {
			kinds = append(kinds, it.Kind)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	t.Setenv("KIYESI_API", srv.URL)
	t.Setenv("KIYESI_TOKEN", goodToken)
	t.Setenv("KIYESI_STATE", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := newAgent(IO{Out: &out, Err: &errOut})
	cmd.SetArgs([]string{"--container", "--minute", "2s", "--config", "/nonexistent.yaml"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("%v: %s", err, errOut.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) < 2 || paths[0] != "/v1/agent/connect" {
		t.Fatalf("calls = %v (%s)", paths, errOut.String())
	}
	for _, k := range kinds {
		if k == "scan" || k == "metrics" || k == "logs" {
			t.Errorf("sent %q beside a managed service", k)
		}
	}
	if len(kinds) == 0 || kinds[0] != "heartbeat" {
		t.Errorf("kinds = %v", kinds)
	}
}
