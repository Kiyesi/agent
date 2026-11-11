package githook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/pullcheck"
)

// usageServer records each report as it arrives, raw, and answers status.
func usageServer(t *testing.T, status int) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != UsagePath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("not JSON: %s", b)
		}
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), got...)
	}
}

func testUsage(t *testing.T, api string, env map[string]string, now *time.Time) *Usage {
	t.Helper()
	return &Usage{
		Dir: t.TempDir(), API: api,
		Now:    func() time.Time { return *now },
		Getenv: func(k string) string { return env[k] },
	}
}

func stopReport() Report {
	return Report{Stop: true, Findings: []pullcheck.Finding{
		{Rule: pullcheck.RuleMalicious, Conclusion: "failure", File: "package.json", Snippet: "secret repo line",
			Package: &pullcheck.Package{Ecosystem: "npm", Name: "flatmap-stream", Version: "0.1.1"}},
		{Rule: pullcheck.RuleWorkflow, Conclusion: "neutral", File: ".github/workflows/ci.yml"},
	}}
}

func TestUsageSendsOnlyCountsOnceADay(t *testing.T) {
	srv, got := usageServer(t, http.StatusNoContent)
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	u := testUsage(t, srv.URL, nil, &now)

	u.Count(stopReport())
	u.Count(Report{})
	if err := u.Send(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r := got()
	if len(r) != 1 {
		t.Fatalf("reports: %d", len(r))
	}
	// Only these fields leave the computer: nothing from the repository.
	var keys []string
	for k := range r[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"arch", "checked", "findings", "install", "os", "packages", "report", "since", "stopped", "until", "version"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("fields: %v", keys)
	}
	raw, _ := json.Marshal(r[0])
	for _, s := range []string{"package.json", "secret repo line", "ci.yml"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("the report holds %q: %s", s, raw)
		}
	}
	if r[0]["checked"] != 2.0 || r[0]["stopped"] != 1.0 {
		t.Fatalf("counts: %s", raw)
	}
	if !strings.Contains(string(raw), `"name":"flatmap-stream"`) || !strings.Contains(string(raw), `"workflow":1`) {
		t.Fatalf("findings: %s", raw)
	}
	if len(r[0]["install"].(string)) != 32 {
		t.Fatalf("install: %v", r[0]["install"])
	}

	// Within the day: nothing more is sent, however many pushes.
	u.Count(Report{})
	now = now.Add(23 * time.Hour)
	_ = u.Send(context.Background(), false)
	if len(got()) != 1 {
		t.Fatal("sent twice in a day")
	}
	// A day on: the next report, with the same install and only the new counts.
	now = now.Add(2 * time.Hour)
	_ = u.Send(context.Background(), false)
	r = got()
	if len(r) != 2 || r[1]["install"] != r[0]["install"] || r[1]["report"] == r[0]["report"] || r[1]["checked"] != 1.0 {
		t.Fatalf("second report: %v", r)
	}
}

func TestUsageReportNotReceivedIsSentAgainTheSame(t *testing.T) {
	fail := true
	var mu sync.Mutex
	var reports []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			Report  string `json:"report"`
			Checked int    `json:"checked"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		reports = append(reports, m.Report)
		mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if m.Checked != 1 {
			t.Errorf("the report changed: checked %d", m.Checked)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	u := testUsage(t, srv.URL, nil, &now)
	u.Count(Report{})
	if err := u.Send(context.Background(), false); err == nil {
		t.Fatal("a failed send said nothing")
	}
	// Pushes meanwhile wait for the report after.
	u.Count(Report{})
	u.Count(Report{})
	// Not tried again within the day.
	now = now.Add(time.Hour)
	if u.Due() {
		t.Fatal("tried again within a day of a failure")
	}
	fail = false
	now = now.Add(24 * time.Hour)
	if err := u.Send(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0] != reports[1] {
		t.Fatalf("not the same report: %v", reports)
	}
	if d := u.load(); d.Pending != nil || d.Counts.Checked != 2 {
		t.Fatalf("after: %+v", d)
	}
}

func TestUsageOffSendsAndKeepsNothing(t *testing.T) {
	srv, got := usageServer(t, http.StatusNoContent)
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	for name, env := range map[string]map[string]string{
		"KIYESI_NO_USAGE": {"KIYESI_NO_USAGE": "1"},
		"DO_NOT_TRACK":    {"DO_NOT_TRACK": "1"},
		"turned off":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			u := testUsage(t, srv.URL, env, &now)
			if name == "turned off" {
				u.Count(Report{})
				if err := u.SetOff(true); err != nil {
					t.Fatal(err)
				}
			}
			u.Count(stopReport())
			_ = u.Send(context.Background(), true)
			if st := u.State(); st.On || st.OffBy != name {
				t.Fatalf("state: %+v", st)
			}
			b, _ := os.ReadFile(filepath.Join(u.Dir, UsageFile))
			if strings.Contains(string(b), "install") || strings.Contains(string(b), "checked\":1") {
				t.Fatalf("kept while off: %s", b)
			}
		})
	}
	if len(got()) != 0 {
		t.Fatalf("sent while off: %v", got())
	}
	// DO_NOT_TRACK=0 means it is not set.
	u := testUsage(t, srv.URL, map[string]string{"DO_NOT_TRACK": "0"}, &now)
	if !u.State().On {
		t.Fatal("DO_NOT_TRACK=0 turned it off")
	}
}

func TestUsageOnAgainIsANewInstall(t *testing.T) {
	srv, got := usageServer(t, http.StatusNoContent)
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	u := testUsage(t, srv.URL, nil, &now)
	_ = u.Send(context.Background(), true)
	_ = u.SetOff(true)
	_ = u.SetOff(false)
	_ = u.Send(context.Background(), true)
	r := got()
	if len(r) != 2 || r[0]["install"] == r[1]["install"] {
		t.Fatalf("the old install came back: %v", r)
	}
}

func TestUsageSlowServiceWaitsAtMostTheTimeout(t *testing.T) {
	old := usageTimeout
	usageTimeout = 200 * time.Millisecond
	t.Cleanup(func() { usageTimeout = old })
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	u := testUsage(t, srv.URL, nil, &now)
	start := time.Now()
	if err := u.Send(context.Background(), true); err == nil {
		t.Fatal("no error from a service that never answered")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("waited %s", waited)
	}
}

func TestUsageRefusedReportIsLetGo(t *testing.T) {
	srv, got := usageServer(t, http.StatusBadRequest)
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	u := testUsage(t, srv.URL, nil, &now)
	u.Count(Report{})
	if err := u.Send(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if d := u.load(); d.Pending != nil {
		t.Fatal("a refused report was kept to send again")
	}
	if len(got()) != 1 {
		t.Fatal("not sent")
	}
}

func TestUsageKeepsAtMostTwentyPackages(t *testing.T) {
	var list []Caught
	for i := range 30 {
		list = addCaught(list, pullcheck.Package{Ecosystem: "npm", Name: "p" + string(rune('a'+i)), Version: "1"})
	}
	list = addCaught(list, pullcheck.Package{Ecosystem: "npm", Name: "pa", Version: "1"})
	if len(list) != maxPackages || list[0].Count != 2 {
		t.Fatalf("%d packages, first %+v", len(list), list[0])
	}
}
