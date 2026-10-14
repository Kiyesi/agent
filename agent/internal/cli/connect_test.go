package cli

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/send"
)

const goodToken = "ksv_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func fakeService(t *testing.T, connectStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/agent/connect" {
			w.WriteHeader(connectStatus)
			_, _ = w.Write([]byte(`{"server_id":"6ac8e2ce48aa8a76695e6a48","team_id":"t"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectSavesTheTokenForRootOnly(t *testing.T) {
	etc := t.TempDir()
	t.Setenv("KIYESI_ETC", etc)
	srv := fakeService(t, http.StatusOK)
	code, out, errOut := runCLI(t, "connect", "--token", goodToken, "--api", srv.URL, "--no-service")
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	info, err := os.Stat(filepath.Join(etc, "token"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token mode = %v, want 0600", info.Mode().Perm())
	}
	conf, token, err := loadConnection()
	if err != nil || token != goodToken || conf.API != srv.URL || conf.ServerID != "6ac8e2ce48aa8a76695e6a48" {
		t.Errorf("saved %+v %q %v", conf, token, err)
	}
	if !strings.Contains(out, "Connected") || strings.Contains(out, goodToken) {
		t.Errorf("output = %q (the token must not be printed)", out)
	}
}

func TestConnectRefusals(t *testing.T) {
	t.Setenv("KIYESI_ETC", t.TempDir())
	srv := fakeService(t, http.StatusOK)
	cases := []struct {
		args []string
		code int
		says string
	}{
		{[]string{"--token", "nope", "--api", srv.URL}, ExitUsage, "starts with ksv_"},
		{[]string{"--token", goodToken, "--api", "http://api.example.com"}, ExitUsage, "https://"},
		{[]string{"--token", "ksv_" + strings.Repeat("z", 43), "--api", srv.URL}, ExitNoAccess, "refused this token"},
		{[]string{"--token", goodToken, "--api", "http://127.0.0.1:1"}, ExitNoAccess, "Check the address"},
	}
	for _, c := range cases {
		code, _, errOut := runCLI(t, append([]string{"connect", "--no-service"}, c.args...)...)
		if code != c.code || !strings.Contains(errOut, c.says) {
			t.Errorf("connect %v: exit %d, %q", c.args, code, errOut)
		}
	}
}

func TestUnitFileMakesRoomForTrivy(t *testing.T) {
	if !strings.Contains(unitFileFor("/k", true), "MemoryMax=640M") {
		t.Error("with Trivy the cap should be 640M")
	}
}

func TestUnitFileTakesPrivilegesAway(t *testing.T) {
	u := unitFileFor("/usr/local/bin/kiyesi", false)
	for _, want := range []string{"ExecStart=/usr/local/bin/kiyesi agent", "NoNewPrivileges=yes", "ProtectSystem=strict", "MemoryMax=64M", "CPUQuota=20%", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit file lacks %q", want)
		}
	}
}

// countingAPI records the kinds of item it receives.
type countingAPI struct {
	mu    sync.Mutex
	kinds map[string]int
	down  atomic.Bool
}

func (c *countingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	zr, _ := gzip.NewReader(r.Body)
	body, _ := io.ReadAll(zr)
	var b send.Batch
	_ = json.Unmarshal(body, &b)
	c.mu.Lock()
	for _, it := range b.Items {
		c.kinds[it.Kind]++
	}
	c.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (c *countingAPI) count(kind string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kinds[kind]
}

func TestAgentLoopSendsScansAndHeartbeatsAndSurvivesAnOutage(t *testing.T) {
	api := &countingAPI{kinds: map[string]int{}}
	api.down.Store(true)
	srv := httptest.NewServer(api)
	defer srv.Close()
	out := send.Outbox{Dir: t.TempDir(), MaxBytes: 1 << 20}
	a := agentLoop{
		client: send.NewClient(srv.URL, goodToken),
		outbox: out,
		scan: func(context.Context) (scan.Report, error) {
			return scan.Report{Schema: scan.Schema, StartedAt: time.Now()}, nil
		},
		scanEvery: 200 * time.Millisecond,
		beatEvery: 50 * time.Millisecond,
		now:       time.Now,
		log:       io.Discard,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.run(ctx); close(done) }()

	time.Sleep(300 * time.Millisecond)
	if api.count("scan")+api.count("heartbeat") != 0 {
		t.Fatal("something was sent while the service was down")
	}
	if out.Len() == 0 {
		t.Fatal("nothing waited on disk during the outage")
	}
	api.down.Store(false)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && (api.count("scan") < 2 || out.Len() > 0) {
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if api.count("scan") < 2 || api.count("heartbeat") < 3 {
		t.Errorf("received %d scans and %d heartbeats", api.count("scan"), api.count("heartbeat"))
	}
}

func TestAgentLoopWithoutScansSendsOnlyHeartbeats(t *testing.T) {
	api := &countingAPI{kinds: map[string]int{}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	scanned := 0
	a := agentLoop{
		client: send.NewClient(srv.URL, goodToken),
		outbox: send.Outbox{Dir: t.TempDir(), MaxBytes: 1 << 20},
		scan: func(context.Context) (scan.Report, error) {
			scanned++
			return scan.Report{Schema: scan.Schema, StartedAt: time.Now()}, nil
		},
		scanEvery: 0,
		beatEvery: 50 * time.Millisecond,
		now:       time.Now,
		log:       io.Discard,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	a.run(ctx)
	if scanned != 0 || api.count("scan") != 0 {
		t.Errorf("scanned %d times, sent %d scans", scanned, api.count("scan"))
	}
	if api.count("heartbeat") < 2 {
		t.Errorf("sent %d heartbeats", api.count("heartbeat"))
	}
}
