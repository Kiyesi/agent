package send

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kiyesi/kiyesi/agent/internal/keys"
	"github.com/kiyesi/kiyesi/agent/internal/software"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/collect"
	"github.com/kiyesi/kiyesi/agent/internal/jobs"
	"github.com/kiyesi/kiyesi/agent/internal/machine"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

type fakeAPI struct {
	mu      sync.Mutex
	answers []int // status for each request, last one repeats
	bodies  [][]byte
	auth    []string
	gz      []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	zr, err := gzip.NewReader(r.Body)
	if err == nil {
		body, _ := io.ReadAll(zr)
		f.bodies = append(f.bodies, body)
	}
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.gz = append(f.gz, r.Header.Get("Content-Encoding"))
	status := f.answers[min(len(f.bodies)-1, len(f.answers)-1)]
	w.WriteHeader(status)
}

func report() scan.Report {
	return scan.Report{
		Schema: scan.Schema, StartedAt: time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC), ReportFile: "/var/lib/kiyesi/report.txt",
		Checks: []scan.CheckResult{{ID: "ssh", Findings: []scan.Finding{{Fix: "mysql -u root -pTopSecret99 app", Why: "DB_PASSWORD=hunter2hunter2"}}}},
	}
}

func TestSecretsAreMaskedBeforeSending(t *testing.T) {
	api := &fakeAPI{answers: []int{202}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	out := Outbox{Dir: t.TempDir(), MaxBytes: 1 << 20}
	if err := out.Put(Scan(report(), time.Now()), time.Now()); err != nil {
		t.Fatal(err)
	}
	sent, err := out.Flush(context.Background(), NewClient(srv.URL, "ksv_token"))
	if err != nil || sent != 1 {
		t.Fatalf("sent %d, %v", sent, err)
	}
	body := string(api.bodies[0])
	for _, secret := range []string{"TopSecret99", "hunter2hunter2"} {
		if strings.Contains(body, secret) {
			t.Fatalf("%q left the server: %s", secret, body)
		}
	}
	if strings.Contains(body, "report.txt") {
		t.Error("the local report path was sent")
	}
	if api.auth[0] != "Bearer ksv_token" || api.gz[0] != "gzip" {
		t.Errorf("headers: %q %q", api.auth[0], api.gz[0])
	}
	if out.Len() != 0 {
		t.Error("a sent batch stayed in the outbox")
	}
}

func TestAFailedSendKeepsTheBatchAndItsID(t *testing.T) {
	api := &fakeAPI{answers: []int{503, 503, 202}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	out := Outbox{Dir: t.TempDir(), MaxBytes: 1 << 20}
	b := Heartbeat(time.Now())
	_ = out.Put(b, time.Now())
	c := NewClient(srv.URL, "t")
	for range 2 {
		if _, err := out.Flush(context.Background(), c); err == nil {
			t.Fatal("expected an error while the service is busy")
		}
		if out.Len() != 1 {
			t.Fatal("the batch was lost")
		}
	}
	if sent, err := out.Flush(context.Background(), c); err != nil || sent != 1 {
		t.Fatalf("sent %d, %v", sent, err)
	}
	var ids []string
	for _, raw := range api.bodies {
		var got Batch
		_ = json.Unmarshal(raw, &got)
		ids = append(ids, got.BatchID)
	}
	if ids[0] != b.BatchID || ids[1] != b.BatchID || ids[2] != b.BatchID {
		t.Errorf("the batch id changed between tries: %v", ids)
	}
}

func TestRefusedTokenStopsAndRejectedBatchIsDropped(t *testing.T) {
	api := &fakeAPI{answers: []int{401}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	out := Outbox{Dir: t.TempDir(), MaxBytes: 1 << 20}
	_ = out.Put(Heartbeat(time.Now()), time.Now())
	if _, err := out.Flush(context.Background(), NewClient(srv.URL, "t")); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("err = %v", err)
	}
	if out.Len() != 1 {
		t.Error("a batch was dropped because of a token problem")
	}
	api.answers = []int{413}
	api.bodies = nil
	if _, err := out.Flush(context.Background(), NewClient(srv.URL, "t")); err != nil {
		t.Errorf("err = %v", err)
	}
	if out.Len() != 0 {
		t.Error("a batch the service refuses for good should be dropped")
	}
}

func TestOutboxDropsTheOldestOverItsLimit(t *testing.T) {
	out := Outbox{Dir: t.TempDir(), MaxBytes: 2000}
	start := time.Now()
	var last Batch
	for i := range 40 {
		last = Heartbeat(start)
		_ = out.Put(last, start.Add(time.Duration(i)*time.Second))
	}
	files, _ := out.files()
	var total int64
	for _, f := range files {
		info, _ := f.Info()
		total += info.Size()
	}
	if total > 2000 || len(files) == 0 {
		t.Errorf("outbox holds %d bytes in %d files", total, len(files))
	}
	if !strings.Contains(files[len(files)-1].Name(), last.BatchID) {
		t.Error("the newest batch was dropped")
	}
}

func TestCheckAPI(t *testing.T) {
	for api, ok := range map[string]bool{
		"https://api.example.com": true, "http://localhost:8080": true, "http://127.0.0.1:8080": true,
		"http://api.example.com": false, "api.example.com": false, "ftp://x": false,
	} {
		if err := CheckAPI(api); (err == nil) != ok {
			t.Errorf("CheckAPI(%q) = %v", api, err)
		}
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	for n := range 30 {
		d := Backoff(n, time.Second, 5*time.Minute)
		if d < 0 || d > 5*time.Minute {
			t.Fatalf("Backoff(%d) = %v", n, d)
		}
	}
	if Backoff(0, time.Second, time.Hour) > time.Second {
		t.Error("the first wait should be at most the base")
	}
}

func TestNewIDIsAUUID(t *testing.T) {
	id := NewID()
	if len(id) != 36 || id[14] != '4' || !bytes.ContainsAny([]byte{id[19]}, "89ab") {
		t.Errorf("id = %s", id)
	}
	_ = os.Remove
}

// The API's tests validate this file against the API's schema, so the
// agent and the API cannot drift apart.
func TestBatchGoldenForTheAPI(t *testing.T) {
	// A fixed machine, so the files do not change with the computer the
	// tests run on.
	defer withMachineHash(machine.Of("4c4c4544004a4b1080354ac04f4e3332"))()
	r := report()
	r.Version = "0.2.0"
	r.Host = scan.Host{Name: "checkout-api-prod", OS: "Ubuntu 24.04", Tested: true, Root: true}
	r.Grade = scan.Grade{Score: 95, Letter: "A", BasedOn: 22, Total: 22}
	r.Counts = scan.Counts{Warnings: 1, Passed: 21, Run: 22}
	r.Home = scan.Home{Code: "NG", Name: "Nigeria"}
	r.Checks[0].Name, r.Checks[0].Area, r.Checks[0].Status = "SSH settings", "security", "fail"
	r.Checks[0].Findings[0].Check, r.Checks[0].Findings[0].Severity, r.Checks[0].Findings[0].Sentence = "ssh", "warning", "SSH allows password login"
	r.Checks[0].Findings[0].AutoFix = "ssh-password"
	at := time.Date(2026, 10, 9, 10, 0, 5, 0, time.UTC)
	cpu, load, avg, p95 := 31.5, 0.42, 12.5, 40.0
	used, limit := uint64(209715200), uint64(536870912)
	m := &collect.Metrics{
		CPUPercent: &cpu,
		Load1:      &load,
		Memory:     &collect.Memory{TotalBytes: 2048000000, UsedBytes: 1500000000, SwapTotalBytes: 2147483648, SwapUsedBytes: 0},
		Disks:      []collect.Disk{{Mount: "/", UsedBytes: 20000000000, TotalBytes: 50000000000}},
		Net:        &collect.Net{RxBytesPerSec: 1200, TxBytesPerSec: 3400},
		Containers: []collect.Container{{Name: "checkout-api", CPUPercent: &cpu, MemBytes: &used, MemLimitBytes: &limit}},
		// One request figure for a named site, one for no site in particular.
		HTTP: []collect.EndpointStats{{Endpoint: "GET /api/users/:id", Site: "shop.example.com", Requests: 120, Errors: 2, AvgMs: &avg, P95Ms: &p95},
			{Endpoint: "GET /health", Requests: 60, Errors: 0, AvgMs: nil, P95Ms: nil}},
		HTTPSource: "caddy (container)",
	}
	events := []collect.Event{
		{Kind: "image_changed", Subject: "checkout-api", Detail: "checkout-api:3.8.1"},
		{Kind: "signin", Subject: "ada", Detail: "publickey", Address: "198.51.100.7", At: "2026-10-09T09:59:41Z"},
	}
	logs := &collect.Logs{Lines: []collect.LogLine{
		{At: at.Add(-50 * time.Second), Source: "checkout-api", Kind: "container", Level: "info", Text: "Connecting to redis://default:" + "hunter2-not-real" + "@redis:6379"},
		{At: at.Add(-40 * time.Second), Source: "checkout-api", Kind: "container", Level: "error", Text: "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory"},
		{At: at.Add(-30 * time.Second), Source: "nginx", Kind: "file", Level: "error", Text: `203.0.113.9 - - [09/Oct/2026:10:00:05 +0000] "POST /api/orders HTTP/1.1" 502 157 "-" "curl/8.5.0"`},
		{At: at.Add(-25 * time.Second), Source: "nginx shop.example.com", Kind: "file", Level: "info", Text: `203.0.113.9 - - [09/Oct/2026:10:00:10 +0000] "GET /api/users/7 HTTP/1.1" 200 512 "-" "curl/8.5.0"`},
		{At: at.Add(-20 * time.Second), Source: "kernel", Kind: "journal", Level: "error", Text: "Out of memory: Killed process 21877 (node)"},
	}, Dropped: 0}
	// A server with no timed jobs: an empty list, which JSON leaves out.
	noJobs := Heartbeat(at)
	noJobs.Items = append(noJobs.Items, Jobs(at, nil, []jobs.Schedule{})...)
	batches := map[string]Batch{"batch-scan.json": Scan(r, at), "batch-heartbeat.json": Heartbeat(at), "batch-minute.json": Minute(at, m, events, logs), "batch-no-jobs.json": noJobs,
		// After sudo kiyesi fix: the new scan, a change made and one undone.
		"batch-fixed.json": Fixes(r, at, []Fixed{
			{ID: "7f3a", Fix: "ssh-password", Done: "SSH password login off", User: "ada"},
			{ID: "1c0e", Fix: "firewall", Done: "Firewall on", User: "ada", Undo: true},
		}),
		// Who can sign in with a key, and a key removal by kiyesi keys remove.
		"batch-access.json": Items(at,
			Item{Kind: "fixed", At: at.UTC().Format(time.RFC3339), Fixed: &Fixed{ID: "3876", Fix: "keys", Done: "Removed login key SHA256:BEvNIvJXhPSZ6sZYlp+jSrx2h7QWco8li1kZOHLgNTk (ci deploy) from ada", User: "ada"}},
			Access(at, []keys.Key{
				{User: "ada", Fingerprint: "SHA256:FTTdNdFL7P1Edcs9NJAoKniBAlw3N76qvPVqzpuVeW8", Type: "ssh-ed25519", Comment: "ada@laptop", ChangedAt: at.Add(-48 * time.Hour)},
				{User: "deploy", Fingerprint: "SHA256:BEvNIvJXhPSZ6sZYlp+jSrx2h7QWco8li1kZOHLgNTk", Type: "ssh-rsa", Comment: "ci deploy", ChangedAt: at.Add(-72 * time.Hour), Restricted: true},
			}),
		),
		"batch-no-keys.json": Items(at, Access(at, nil)),
		// What is installed, with the settings kiyesi compare sets side by side.
		"batch-software.json": Items(at, Software(at, software.List{
			OS:          software.OS{ID: "ubuntu", VersionID: "24.04", Codename: "noble", Name: "Ubuntu 24.04.1 LTS"},
			Kernel:      "6.8.0-45-generic",
			Packages:    []software.Package{{Name: "openssl", Source: "openssl", Version: "3.0.13-0ubuntu3.4", Manager: "dpkg"}},
			Containers:  []software.Container{{Name: "checkout-api", Image: "ghcr.io/acme/checkout:3.8.1", RestartPolicy: "unless-stopped"}},
			MemoryBytes: 2048000000,
			Settings: &software.Settings{
				Ports: []int{22, 80, 443}, Services: []string{"nginx.service", "ssh.service"},
				SSH:      &software.SSHSettings{PasswordLogin: false, RootLogin: false, Ports: []int{22}},
				Firewall: "ufw", Timezone: "Etc/UTC",
			},
		})),
	}
	for name, b := range batches {
		// A fixed id, so the files only change when the shape does.
		b.BatchID = "0f8b8c3e-6f5d-4b7a-9c1e-2d3f4a5b6c7d"
		body, err := Encode(b)
		if err != nil {
			t.Fatal(err)
		}
		zr, _ := gzip.NewReader(bytes.NewReader(body))
		raw, _ := io.ReadAll(zr)
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, raw, "", "  ")
		if err := os.WriteFile("testdata/"+name, pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// withMachineHash makes batches carry hash, and returns the undo.
func withMachineHash(hash string) func() {
	before := machineHash
	machineHash = func() string { return hash }
	return func() { machineHash = before }
}

// Every batch carries the machine hash next to the agent version, and
// leaves the field out, never empty, when the server has no machine ID.
func TestBatchesCarryTheMachineHash(t *testing.T) {
	at := time.Date(2026, 10, 9, 10, 0, 5, 0, time.UTC)
	hash := machine.Of("4c4c4544004a4b1080354ac04f4e3332")
	decode := func(b Batch) map[string]any {
		t.Helper()
		body, err := Encode(b)
		if err != nil {
			t.Fatal(err)
		}
		zr, _ := gzip.NewReader(bytes.NewReader(body))
		raw, _ := io.ReadAll(zr)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	undo := withMachineHash(hash)
	for name, b := range map[string]Batch{"heartbeat": Heartbeat(at), "minute": Minute(at, nil, nil, nil), "scan": Scan(report(), at)} {
		if got := decode(b)["machine_hash"]; got != hash {
			t.Errorf("%s: machine_hash = %v, want %s", name, got, hash)
		}
	}
	undo()
	defer withMachineHash("")()
	for name, b := range map[string]Batch{"heartbeat": Heartbeat(at), "scan": Scan(report(), at)} {
		if got, ok := decode(b)["machine_hash"]; ok {
			t.Errorf("%s: machine_hash = %v, want it left out", name, got)
		}
	}
}

// Each reply may name the team's home country; the agent keeps it for the
// next scan. Anything that is not a two-letter code is ignored.
// Each request figure names its site, and leaves the field out when the
// site is unknown, so an API from before sites reads it as before.
func TestMinuteNamesTheSiteOfRequests(t *testing.T) {
	at := time.Date(2026, 10, 9, 10, 0, 5, 0, time.UTC)
	m := &collect.Metrics{HTTP: []collect.EndpointStats{
		{Endpoint: "GET /health", Site: "shop.example.com", Requests: 3},
		{Endpoint: "GET /health", Site: "blog.example.com", Requests: 1},
		{Endpoint: "GET /health", Requests: 2},
	}}
	body, err := Encode(Minute(at, m, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	zr, _ := gzip.NewReader(bytes.NewReader(body))
	raw, _ := io.ReadAll(zr)
	var b struct {
		Items []struct {
			Metrics *struct {
				HTTP []map[string]any `json:"http"`
			} `json:"metrics"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	var http []map[string]any
	for _, it := range b.Items {
		if it.Metrics != nil {
			http = it.Metrics.HTTP
		}
	}
	if len(http) != 3 || http[0]["site"] != "shop.example.com" || http[1]["site"] != "blog.example.com" || http[0]["endpoint"] != "GET /health" {
		t.Fatalf("http = %v", http)
	}
	if _, ok := http[2]["site"]; ok {
		t.Errorf("an unknown site must be left out: %v", http[2])
	}
	for _, e := range http {
		for _, k := range []string{"endpoint", "requests", "errors", "avg_ms", "p95_ms"} {
			if _, ok := e[k]; !ok {
				t.Errorf("%v has no %s", e, k)
			}
		}
	}
}

func TestRepliesNameTheTeamsHomeCountry(t *testing.T) {
	for _, tc := range []struct {
		reply string
		heard []string
	}{
		{`{"accepted":"x","home_country":"DE"}`, []string{"DE"}},
		{`{"accepted":"x","home_country":null}`, []string{""}},
		{`{"accepted":"x"}`, nil},
		{`{"accepted":"x","home_country":"de"}`, nil},
		{`{"accepted":"x","home_country":"DEU"}`, nil},
		{`not json`, nil},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(tc.reply))
		}))
		var heard []string
		c := NewClient(srv.URL, "ksv_test")
		c.OnHome = func(code string) { heard = append(heard, code) }
		body, _ := Encode(Heartbeat(time.Now()))
		if err := c.deliver(context.Background(), body); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if fmt.Sprint(heard) != fmt.Sprint(tc.heard) {
			t.Errorf("%s: heard %q, want %q", tc.reply, heard, tc.heard)
		}
	}
}

func TestTheServiceCanAskForASlowerPace(t *testing.T) {
	for _, tc := range []struct {
		reply string
		heard string
	}{
		{`{"pace":{"beat_seconds":300,"scan_seconds":21600,"collect":false}}`, "{5m0s 6h0m0s false}"},
		{`{"pace":{"beat_seconds":300,"scan_seconds":0,"collect":false}}`, "{5m0s 0s false}"},
		{`{"pace":{"beat_seconds":60,"scan_seconds":900,"collect":true}}`, "{1m0s 15m0s true}"},
		// Out of bounds, or not said: nothing heard.
		{`{"pace":{"beat_seconds":5,"scan_seconds":900,"collect":true}}`, ""},
		{`{"pace":{"beat_seconds":300,"scan_seconds":60,"collect":false}}`, ""},
		{`{"pace":{"beat_seconds":3600,"scan_seconds":900,"collect":true}}`, ""},
		{`{"accepted":"x"}`, ""},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(tc.reply))
		}))
		heard := ""
		c := NewClient(srv.URL, "ksv_test")
		c.OnPace = func(p Pace) { heard = fmt.Sprint(p) }
		body, _ := Encode(Heartbeat(time.Now()))
		if err := c.deliver(context.Background(), body); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if heard != tc.heard {
			t.Errorf("%s: heard %q, want %q", tc.reply, heard, tc.heard)
		}
	}
}

// After time without the service, the newest scan goes first, so the
// dashboard shows the server as it is now; the rest follow oldest first,
// and a limit counts the scan among the batches it allows.
func TestFlushSendsTheNewestScanFirst(t *testing.T) {
	api := &fakeAPI{answers: []int{202}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	out := Outbox{Dir: t.TempDir(), MaxBytes: 1 << 20}
	start := time.Date(2026, 10, 23, 14, 0, 0, 0, time.UTC)
	scanAt := func(at time.Time) Batch {
		r := report()
		r.StartedAt = at
		return Scan(r, at)
	}
	waiting := []Batch{Heartbeat(start), scanAt(start.Add(time.Minute)), Heartbeat(start.Add(2 * time.Minute)), scanAt(start.Add(3 * time.Minute)), Heartbeat(start.Add(4 * time.Minute))}
	for i, b := range waiting {
		if err := out.Put(b, start.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	order := func() []string {
		var ids []string
		for _, raw := range api.bodies {
			var got Batch
			_ = json.Unmarshal(raw, &got)
			ids = append(ids, got.BatchID)
		}
		return ids
	}
	c := NewClient(srv.URL, "t")
	if sent, err := out.FlushUpTo(context.Background(), c, 2, nil); err != nil || sent != 2 {
		t.Fatalf("sent %d, %v", sent, err)
	}
	if got := order(); got[0] != waiting[3].BatchID || got[1] != waiting[0].BatchID {
		t.Fatalf("first two sent %v, want the newest scan then the oldest heartbeat", got)
	}
	if sent, err := out.Flush(context.Background(), c); err != nil || sent != 3 {
		t.Fatalf("sent %d, %v", sent, err)
	}
	want := []string{waiting[3].BatchID, waiting[0].BatchID, waiting[1].BatchID, waiting[2].BatchID, waiting[4].BatchID}
	if got := order(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sent %v, want %v", got, want)
	}
}
