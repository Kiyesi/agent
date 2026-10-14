package cli

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestErrorsListsGroupsWithFileAndLine(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "errors", "--frontend", "STOREFRONT-WEB", "--since", "7d")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if q := lastLogs(); q.Get("frontend") != "f1" || q.Get("range") != "7d" {
		t.Errorf("query = %v", q)
	}
	for _, want := range []string{
		"Today: 214 errors in 1 group.",
		"214      163     TypeError: Cannot read properties of undefined (reading 'amount')   src/components/CheckoutSummary.tsx:48",
		"version 2.14.0",
		"/assets/index-3f9a.js:1 (no source map)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, errOut := runCLI(t, "errors", "--since", "forever"); code != ExitUsage || !strings.Contains(errOut, "--since") {
		t.Errorf("bad since: %d %q", code, errOut)
	}
}

func TestSourcemapsUploadSendsEachMapGzipped(t *testing.T) {
	t.Setenv("KIYESI_ETC", t.TempDir())
	var mu sync.Mutex
	got := map[string]string{}
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sourcemaps" || r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(zr)
		mu.Lock()
		q := r.URL.Query()
		got[q.Get("frontend")+"|"+q.Get("version")+"|"+q.Get("path")] = string(body)
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	dist := t.TempDir()
	for name, data := range map[string]string{
		"assets/index-3f9a.js.map":  `{"version":3,"mappings":"AAAA"}`,
		"assets/index-3f9a.js":      "console.log(1)",
		"node_modules/x/x.js.map":   `{"mappings":""}`,
		"assets/vendor-aa11.js.map": `{"version":3,"mappings":"BBBB"}`,
		// As Turbopack builds: the script points to a map with another name.
		"chunks/3ujp9.js":     "x()\n//# sourceMappingURL=0p0if.js.map",
		"chunks/0p0if.js.map": `{"version":3,"mappings":"CCCC"}`,
	} {
		p := filepath.Join(dist, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(data), 0o644)
	}
	token := "kdp_" + strings.Repeat("a", 43)
	code, out, errOut := runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=" + token},
		"sourcemaps", "upload", "--frontend", "storefront-web", "--version", "2.14.0", "--delete", "--api", srv.URL, dist)
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if auth != "Bearer "+token || len(got) != 3 ||
		got["storefront-web|2.14.0|chunks/3ujp9.js.map"] != `{"version":3,"mappings":"CCCC"}` ||
		got["storefront-web|2.14.0|assets/index-3f9a.js.map"] != `{"version":3,"mappings":"AAAA"}` ||
		got["storefront-web|2.14.0|assets/vendor-aa11.js.map"] == "" {
		t.Errorf("sent %v with %q", got, auth)
	}
	if !strings.Contains(out, "Uploaded 3 source maps for version 2.14.0") || !strings.Contains(out, "Removed them from the folder") {
		t.Errorf("out = %q", out)
	}
	if _, err := os.Stat(filepath.Join(dist, "assets/index-3f9a.js.map")); err == nil {
		t.Error("--delete left the map in the folder")
	}
	if _, err := os.Stat(filepath.Join(dist, "assets/index-3f9a.js")); err != nil {
		t.Error("--delete removed the script")
	}
	if code, _, errOut := runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=" + token}, "sourcemaps", "upload", "--api", srv.URL, dist); code != ExitUsage || !strings.Contains(errOut, "--version") {
		t.Errorf("no version: %d %q", code, errOut)
	}
}
