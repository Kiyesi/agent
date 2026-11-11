package githook

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const listBody = `{"sha":"abc","fetchedAt":"2026-11-10T09:00:00.000Z"}` + "\n" + `["MAL-2025-1","npm","left-pad-x",1,[],[]]` + "\n"

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// listServer serves the list as the service does: gzip, with an ETag, and
// 304 when asked with it.
func listServer(t *testing.T, body string) (*httptest.Server, *int32, *string) {
	t.Helper()
	var calls int32
	var lastIfNoneMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != ListPath {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Accept-Encoding") != "gzip" || !strings.HasPrefix(r.Header.Get("User-Agent"), "kiyesi-cli/") {
			http.Error(w, "headers", http.StatusBadRequest)
			return
		}
		lastIfNoneMatch = r.Header.Get("If-None-Match")
		if lastIfNoneMatch == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(gz(t, body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &lastIfNoneMatch
}

func TestListIsFetchedUnpackedKeptAndAskedWithItsTag(t *testing.T) {
	srv, calls, inm := listServer(t, listBody)
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	l := &List{Dir: filepath.Join(t.TempDir(), "kiyesi"), API: srv.URL + "/", Now: func() time.Time { return now }}
	st := l.Refresh(ctx, false)
	if !st.Refreshed || !st.Present || st.Failed != "" || st.FetchedAt.Format(time.RFC3339) != "2026-11-10T09:00:00Z" {
		t.Fatalf("state = %+v", st)
	}
	if b, _ := os.ReadFile(l.Path()); string(b) != listBody {
		t.Fatalf("kept %q", b)
	}
	// Under 6 hours old: not asked again.
	now = now.Add(5 * time.Hour)
	if st := l.Refresh(ctx, false); st.Refreshed || atomic.LoadInt32(calls) != 1 {
		t.Errorf("asked again too soon: %+v", st)
	}
	// Over 6 hours: asked with the tag, and 304 keeps the copy.
	now = now.Add(2 * time.Hour)
	st = l.Refresh(ctx, false)
	if !st.Refreshed || *inm != `"v1"` || atomic.LoadInt32(calls) != 2 || !st.CheckedAt.Equal(now) {
		t.Errorf("304 path: %+v, If-None-Match %q", st, *inm)
	}
	if b, _ := os.ReadFile(l.Path()); string(b) != listBody {
		t.Error("the copy changed on 304")
	}
	// No stray temp files beside it.
	ents, _ := os.ReadDir(l.Dir)
	if len(ents) != 2 {
		t.Errorf("cache folder holds %v", ents)
	}
}

// A body that is gzip without the header is unpacked too; a plain one is kept as it is.
func TestListGzipBodyWithoutHeader(t *testing.T) {
	for name, body := range map[string][]byte{"gz body": gz(t, listBody), "plain": []byte(listBody)} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
			defer srv.Close()
			l := &List{Dir: t.TempDir(), API: srv.URL}
			if st := l.Refresh(ctx, true); st.Failed != "" || !st.Present {
				t.Fatalf("%+v", st)
			}
			if b, _ := os.ReadFile(l.Path()); string(b) != listBody {
				t.Errorf("kept %q", b)
			}
		})
	}
}

// Offline: the copy stays, the failure is said, and the next push does not
// wait again for a while.
func TestListOfflineKeepsTheCopy(t *testing.T) {
	old := fetchTimeout
	fetchTimeout = 200 * time.Millisecond
	t.Cleanup(func() { fetchTimeout = old })
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(block); srv.Close() }()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ListFile), []byte(listBody), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	l := &List{Dir: dir, API: srv.URL, Now: func() time.Time { return now }}
	start := time.Now()
	st := l.Refresh(ctx, false)
	if time.Since(start) > 2*time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
	if st.Refreshed || !st.Present || !strings.HasPrefix(st.Failed, "no answer") {
		t.Fatalf("state = %+v", st)
	}
	if Ago(now.Sub(st.FetchedAt)) != "2 days" {
		t.Errorf("age %q", Ago(now.Sub(st.FetchedAt)))
	}
	// The next push, a minute later, does not wait again.
	now = now.Add(time.Minute)
	start = time.Now()
	st = l.Refresh(ctx, false)
	if time.Since(start) > 100*time.Millisecond || st.Failed == "" || !st.Present {
		t.Errorf("waited again: %v, %+v", time.Since(start), st)
	}
	// Nothing listening at all.
	l2 := &List{Dir: t.TempDir(), API: "http://127.0.0.1:1"}
	if st := l2.Refresh(ctx, false); st.Present || !strings.HasPrefix(st.Failed, "could not reach") {
		t.Errorf("no network, no copy: %+v", st)
	}
}

// What is not the list is never kept over the copy; a list over 64 MB
// unpacked is refused without holding it all.
func TestListRefusesWhatIsNotTheList(t *testing.T) {
	big := strings.Repeat("x", maxList+10)
	for name, body := range map[string][]byte{
		"html":     []byte("<html>maintenance</html>"),
		"bomb":     gz(t, `{"sha":"a","fetchedAt":"2026-11-10T09:00:00Z"}`+"\n"+big),
		"bad gzip": {0x1f, 0x8b, 0, 1, 2},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
			defer srv.Close()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ListFile), []byte(listBody), 0o600); err != nil {
				t.Fatal(err)
			}
			l := &List{Dir: dir, API: srv.URL}
			st := l.Refresh(ctx, true)
			if st.Failed == "" {
				t.Fatalf("kept it: %+v", st)
			}
			if b, _ := os.ReadFile(l.Path()); string(b) != listBody {
				t.Error("the copy was replaced")
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv.Close()
	if st := (&List{Dir: t.TempDir(), API: srv.URL}).Refresh(ctx, true); st.Failed != "the service answered 503" {
		t.Errorf("503: %+v", st)
	}
}

func TestAgo(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second: "less than a minute", time.Minute: "1 minute", 5 * time.Minute: "5 minutes",
		time.Hour: "1 hour", 30 * time.Hour: "30 hours", 50 * time.Hour: "2 days",
	} {
		if got := Ago(d); got != want {
			t.Errorf("Ago(%v) = %q, want %q", d, got, want)
		}
	}
}
