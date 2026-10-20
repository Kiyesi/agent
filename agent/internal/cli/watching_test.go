package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLIEnv(t *testing.T, environ []string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(args, IO{Out: &out, Err: &errOut, Environ: append([]string{"NO_COLOR=1"}, environ...)})
	return code, out.String(), errOut.String()
}

func TestDeployWithATokenSaysWhoShippedIt(t *testing.T) {
	t.Setenv("KIYESI_ETC", t.TempDir())
	var got map[string]string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/deploys" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"at":"2026-10-10T10:00:00Z"}`))
	}))
	t.Cleanup(srv.Close)
	gitAuthor = func() string { return "Ada Obi" }
	token := "kdp_" + strings.Repeat("a", 43)
	code, out, errOut := runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=" + token, "GITHUB_ACTOR=ada-ci"},
		"deploy", "--app", "checkout-api", "--version", "3.8.1", "--server", "checkout-api-prod", "--api", srv.URL)
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if auth != "Bearer "+token || got["app"] != "checkout-api" || got["version"] != "3.8.1" || got["server"] != "checkout-api-prod" || got["by"] != "ada-ci" {
		t.Errorf("sent %v with %q", got, auth)
	}
	if !strings.Contains(out, "Marked: checkout-api 3.8.1 on checkout-api-prod, by ada-ci.") {
		t.Errorf("out = %q", out)
	}
	// Without CI, the latest commit's author.
	runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=" + token}, "deploy", "--app", "a", "--version", "1", "--server", "s", "--api", srv.URL)
	if got["by"] != "Ada Obi" {
		t.Errorf("by = %q, want the commit author", got["by"])
	}
	if code, _, errOut := runCLIEnv(t, nil, "deploy", "--app", "a"); code != ExitUsage || !strings.Contains(errOut, "--version") {
		t.Errorf("missing version: %d %s", code, errOut)
	}
	if code, _, errOut := runCLIEnv(t, []string{"KIYESI_DEPLOY_TOKEN=ksv_x"}, "deploy", "--app", "a", "--version", "1"); code != ExitUsage || !strings.Contains(errOut, "not a deploy token") {
		t.Errorf("wrong token kind: %d %s", code, errOut)
	}
}

// On a connected server without sudo, the token cannot be read: the
// answer is sudo, not a deploy token or signing in.
func TestDeployOnAConnectedServerWithoutSudo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	etc := t.TempDir()
	t.Setenv("KIYESI_ETC", etc)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := os.WriteFile(filepath.Join(etc, "agent.yaml"), []byte("api: https://api.kiyesi.dev\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "token"), []byte("ksv_x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLIEnv(t, nil, "deploy", "--app", "a", "--version", "1")
	if code != ExitNoAccess || !strings.Contains(errOut, "Run it with sudo: sudo kiyesi deploy") || strings.Contains(errOut, "KIYESI_DEPLOY_TOKEN") {
		t.Errorf("%d %s", code, errOut)
	}
}

func TestHistoryAndMetricsAsASignedInPerson(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "history", "--since", "yesterday", "--server", "checkout-api-prod")
	if code != ExitOK {
		t.Fatalf("history: exit %d", code)
	}
	// Oldest first, as a log reads.
	deploy := strings.Index(out, "Deployed checkout-api 3.8.1 (by ada)")
	grade := strings.Index(out, "grade went from B 80 to A 95")
	if deploy < 0 || grade < 0 || deploy > grade {
		t.Errorf("history out:\n%s", out)
	}
	if code, out, _ := runCLI(t, "deploys"); code != ExitOK || !strings.Contains(out, "ROLL BACK") || !strings.Contains(out, "IMAGE_TAG=2.13.4 docker compose up -d storefront-web") {
		t.Errorf("deploys: %d %s", code, out)
	}
	if code, out, _ := runCLI(t, "deploys", "--server", "storefront-web-prod"); code != ExitOK || strings.Contains(out, "ROLL BACK") || !strings.Contains(out, "healthy") {
		t.Errorf("deploys on one server: %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "history", "--since", "forever"); code != ExitUsage || !strings.Contains(errOut, "--since") {
		t.Errorf("bad since: %d %s", code, errOut)
	}
	code, out, _ = runCLI(t, "metrics", "checkout-api-prod", "--since", "24h")
	if code != ExitOK {
		t.Fatalf("metrics: exit %d", code)
	}
	for _, want := range []string{"checkout-api-prod, last 24h", "CPU", "now 31.5%  peak 40%", "Disk /", "Requests", "Deploys", "Deployed checkout-api 3.8.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics is missing %q:\n%s", want, out)
		}
	}
}

func TestSparkDrawsTheShape(t *testing.T) {
	points := [][2]float64{{0, 0}, {1, 50}, {2, 100}}
	s := spark(points, 100)
	if []rune(s)[0] != '▁' || []rune(s)[len([]rune(s))-1] != '█' || len([]rune(s)) != sparkWidth {
		t.Errorf("spark = %q", s)
	}
}
