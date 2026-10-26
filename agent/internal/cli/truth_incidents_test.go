package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

// The command line says only what is true: what changed, what the role
// sees, and what applies now.

// route answers one request; "METHOD /path" or "/path" names it.
type routes map[string]func(w http.ResponseWriter, r *http.Request)

// signInWith signs in against the fake API, with some answers replaced.
func signInOver(t *testing.T, over routes) *httptest.Server {
	t.Helper()
	base := fakeAPI(t, 2)
	u, _ := url.Parse(base.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := over[r.Method+" "+r.URL.Path]; ok {
			h(w, r)
			return
		}
		if h, ok := over[r.URL.Path]; ok {
			h(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KIYESI_CONFIG", t.TempDir())
	keychain = noKeychain{}
	openBrowser = func(string) {}
	sleep = func(context.Context, time.Duration) error { return nil }
	if code, out, errOut := runCLI(t, "login", "--api", srv.URL); code != ExitOK {
		t.Fatalf("login: %d %s %s", code, out, errOut)
	}
	return srv
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

const notFound = `{"error":"not_found","message":"Not found."}`

// A role that sees incidents but does not act on them.
var viewOnly = reply(200, `{"role":{"id":"viewer","name":"Viewer"},"levels":{"servers":"view","incidents":"view","settings":"view"},"switches":{},"canSee":"Everything","endsAt":null,"team":"Acme"}`)

func TestAckAndResolveSayWhenItWasAlreadyDone(t *testing.T) {
	signInOver(t, routes{
		"/v1/incidents/INC-11/ack": reply(409, `{"error":"already_fixed","message":"INC-11 is already fixed by Amaka Obi.","state":{"status":"fixed","by":"Amaka Obi","at":"2026-10-10T10:00:00Z"}}`),
		"/v1/incidents/INC-11/fix": reply(409, `{"error":"already_fixed","message":"INC-11 was already fixed by Amaka Obi; your note was not saved.","state":{"status":"fixed","by":"Amaka Obi","at":"2026-10-10T10:00:00Z"}}`),
		"/v1/work/ack":             reply(409, `{"error":"already_acknowledged","message":"It is already acknowledged by Amaka Obi.","state":{"status":"acknowledged","by":"Amaka Obi","at":"2026-10-10T10:00:00Z"}}`),
	})
	// Already true: said, with who, and the command succeeds; it never
	// claims to have done it.
	code, out, errOut := runCLI(t, "ack", "INC-11")
	if code != ExitOK || !strings.Contains(out, "INC-11 is already fixed by Amaka Obi.") || strings.Contains(out, "Acknowledged") {
		t.Errorf("ack: %d %q %q", code, out, errOut)
	}
	code, out, errOut = runCLI(t, "resolve", "INC-11", "--note", "Rolled back")
	if code != ExitOK || !strings.Contains(out, "INC-11 was already fixed by Amaka Obi; your note was not saved.") || strings.Contains(out, "Marked") {
		t.Errorf("resolve: %d %q %q", code, out, errOut)
	}
	code, out, _ = runCLI(t, "ack", "job-a7b8c9")
	if code != ExitOK || !strings.Contains(out, "job-a7b8c9 is already acknowledged by Amaka Obi.") || strings.Contains(out, "Acknowledged job") {
		t.Errorf("work ack: %d %q", code, out)
	}
}

func TestResolveRefusesALongNoteBeforeAskingTheService(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	code, _, errOut := runCLI(t, "resolve", "INC-11", "--note", strings.Repeat("a", 501))
	if code != ExitUsage || !strings.Contains(errOut, "keep it to 500") || len(serverCalls) != 0 {
		t.Errorf("%d %q %v", code, errOut, serverCalls)
	}
}

func TestIncidentShowsWhoActedAndOnlyTheStepsThatApply(t *testing.T) {
	acked := `{"id":"i11","ref":"INC-11","title":"storefront-web: errors","severity":"critical","status":"acknowledged","startedAt":"2026-10-10T09:09:00Z","limited":false,"sentence":"s","acked":{"at":"2026-10-10T09:20:00Z","by":"Amaka Obi"}}`
	signInOver(t, routes{"/v1/incidents/INC-11": reply(200, acked)})
	_, out, _ := runCLI(t, "incident", "INC-11")
	if !strings.Contains(out, "Acknowledged by Amaka Obi, ") || strings.Contains(out, "kiyesi ack INC-11") || !strings.Contains(out, `kiyesi resolve INC-11 --note "what fixed it"`) {
		t.Errorf("acknowledged:\n%s", out)
	}

	fixed := `{"id":"i11","ref":"INC-11","title":"storefront-web: errors","severity":"critical","status":"fixed","startedAt":"2026-10-10T09:09:00Z","limited":false,"sentence":"s","acked":{"at":"2026-10-10T09:20:00Z","by":"Amaka Obi"},"fixed":{"at":"2026-10-10T10:00:00Z","by":"Ada Obi","note":"Rolled back to 2.13.4"}}`
	signInOver(t, routes{"/v1/incidents/INC-11": reply(200, fixed)})
	_, out, _ = runCLI(t, "incident", "INC-11")
	if !strings.Contains(out, "Fixed by Ada Obi, ") || !strings.Contains(out, "What fixed it: Rolled back to 2.13.4") || strings.Contains(out, "kiyesi resolve") {
		t.Errorf("fixed:\n%s", out)
	}

	// A role that cannot act is not told to.
	signInOver(t, routes{"/v1/me/access": viewOnly})
	_, out, _ = runCLI(t, "incident", "INC-11")
	if strings.Contains(out, "kiyesi ack") || strings.Contains(out, "kiyesi resolve") {
		t.Errorf("view only:\n%s", out)
	}
	_, out, _ = runCLI(t, "mine")
	if strings.Contains(out, "kiyesi ack") || strings.Contains(out, "kiyesi assign") {
		t.Errorf("mine, view only:\n%s", out)
	}
}

func TestExplainForAClientIsANoAccessExit(t *testing.T) {
	signInOver(t, routes{"/v1/incidents/INC-11": reply(200, `{"id":"i11","ref":"INC-11","title":"t","severity":"critical","status":"open","startedAt":"2026-10-10T09:09:00Z","limited":true}`)})
	if code, _, errOut := runCLI(t, "explain", "INC-11"); code != ExitNoAccess || !strings.Contains(errOut, "for your team") {
		t.Errorf("%d %q", code, errOut)
	}
}

func TestAssignSaysWhenYouCannotTakeItAndKnowsYouByName(t *testing.T) {
	signInForTest(t)
	serverCalls = nil
	// Giving it to yourself by name: you are not told on your own channel.
	code, out, _ := runCLI(t, "assign", "job-a7b8c9", "Ada")
	if code != ExitOK || !strings.Contains(out, "is yours") || strings.Contains(out, "They are told") {
		t.Errorf("by name: %d %q", code, out)
	}
	signInOver(t, routes{"/v1/work/suggest": reply(200, `{"suggestion":null,"candidates":[{"id":"u2","name":"Ifeoma Nwosu","open":2,"you":false}],"notListed":[]}`)})
	code, _, errOut := runCLI(t, "assign", "job-a7b8c9", "me")
	if code != ExitNoAccess || !strings.Contains(errOut, "You cannot take this: your role does not act on it.") {
		t.Errorf("me: %d %q", code, errOut)
	}
}

func TestKiyesiAloneClaimsNothingAboutListsTheRoleCannotSee(t *testing.T) {
	signInOver(t, routes{
		"/v1/incidents": reply(404, notFound),
		"/v1/work":      reply(404, notFound),
		"/v1/servers":   reply(404, notFound),
		"/v1/uptime":    reply(200, `{"checks":[],"running":true}`),
	})
	code, out, _ := runCLI(t)
	if code != ExitOK || !strings.Contains(out, "Nothing needs you now.\n") || strings.Contains(out, "No servers") || strings.Contains(out, "incidents") || strings.Contains(out, "Settings") {
		t.Errorf("%d\n%s", code, out)
	}
}

func TestKiyesiAloneCountsOnlyServersThatReported(t *testing.T) {
	seen := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339)
	signInOver(t, routes{
		"/v1/incidents": reply(200, `{"incidents":[]}`),
		"/v1/work":      reply(200, `{"people":[]}`),
		"/v1/uptime":    reply(200, `{"checks":[]}`),
		"/v1/servers": reply(200, `{"servers":[
			{"id":"s1","name":"web-1","connected":true,"state":"connected","lastSeenAt":"`+seen+`"},
			{"id":"s2","name":"web-2","connected":false,"state":"waiting"},
			{"id":"s3","name":"web-3","connected":true,"state":"connected"},
			{"id":"s4","name":"old","connected":false,"state":"disconnected","lastSeenAt":"`+seen+`"}]}`),
	})
	_, out, _ := runCLI(t)
	for _, want := range []string{"web-2 is waiting to connect.", "web-3 has never reported."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "all reporting") {
		t.Errorf("not all report:\n%s", out)
	}
	var b strings.Builder
	printNow(&b, nowResult{Servers: 2, Reporting: 1, Next: "kiyesi servers"})
	if !strings.Contains(b.String(), "1 of 2 servers reporting") {
		t.Errorf("got %s", b.String())
	}
	b.Reset()
	printNow(&b, nowResult{Next: "kiyesi servers"})
	if strings.Contains(b.String(), "Add one") {
		t.Errorf("someone who cannot add a server is not told to:\n%s", b.String())
	}
}

func TestStatusPostSaysWhenNobodyWasEmailed(t *testing.T) {
	signInOver(t, routes{"/v1/status-pages": reply(200, `{"pages":[{"id":"sp1","slug":"acme-status","title":"Acme status","url":"https://status.kiyesi.dev/acme-status","on":false,"subscribers":3,"components":[]}]}`)})
	code, out, _ := runCLI(t, "status", "post", "Fixing it.", "--state", "fixing")
	if code != ExitOK || !strings.Contains(out, "The page is not public, so nobody was emailed.") || strings.Contains(out, "Subscribers are emailed") {
		t.Errorf("%d %q", code, out)
	}
	signInOver(t, routes{"/v1/status-pages": reply(200, `{"pages":[]}`)})
	code, _, errOut := runCLI(t, "status", "post", "Fixing it.")
	if code != ExitUsage || !strings.Contains(errOut, "No status page yet") || strings.Contains(errOut, `""`) {
		t.Errorf("none: %d %q", code, errOut)
	}
}

func TestAlertsTestIsForOwnersAndAdmins(t *testing.T) {
	signInOver(t, routes{"/v1/alerts/channels": reply(404, notFound)})
	if code, _, errOut := runCLI(t, "alerts", "test"); code != ExitNoAccess || !strings.Contains(errOut, "Testing alert channels is for owners and admins.") {
		t.Errorf("hidden: %d %q", code, errOut)
	}
	signInOver(t, routes{"/v1/alerts/channels/c1/test": reply(403, `{"error":"not_allowed","message":"Your role does not allow this."}`)})
	if code, out, errOut := runCLI(t, "alerts", "test"); code != ExitNoAccess || strings.Contains(out, "FAIL") || !strings.Contains(errOut, "for owners and admins") {
		t.Errorf("view only: %d %q %q", code, out, errOut)
	}
	signInOver(t, routes{"/v1/alerts/channels": reply(200, `{"channels":[{"id":"c2","kind":"telegram","name":"Telegram","linked":false}]}`)})
	if code, _, errOut := runCLI(t, "alerts", "test"); code != ExitUsage || !strings.Contains(errOut, "No test sent: no channel is linked yet.") {
		t.Errorf("unlinked: %d %q", code, errOut)
	}
}

func TestMuteOffSaysWhenNothingWasMuted(t *testing.T) {
	signInOver(t, routes{"DELETE /v1/servers/s1/mute": reply(200, `{"ended":false}`)})
	if code, out, _ := runCLI(t, "mute", "checkout-api-prod", "off"); code != ExitOK || out != "Alerts for checkout-api-prod were not muted.\n" {
		t.Errorf("%d %q", code, out)
	}
	signInOver(t, routes{"DELETE /v1/servers/s1/mute": reply(200, `{"ended":true}`)})
	if _, out, _ := runCLI(t, "mute", "checkout-api-prod", "off"); out != "Alerts for checkout-api-prod are on again.\n" {
		t.Errorf("%q", out)
	}
}

func TestUptimeSaysWhenChecksArePaused(t *testing.T) {
	seen := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339)
	paused := reply(200, `{"checks":[{"id":"u1","name":"Shop","url":"https://shop.example.com","status":"down","last":{"at":"`+seen+`","ok":false}}],"running":false}`)
	signInOver(t, routes{"GET /v1/uptime": paused})
	_, out, _ := runCLI(t, "uptime")
	if !strings.Contains(out, "Paused on the free plan until the team adds credit.") || !strings.Contains(out, "PAUSED") || strings.Contains(out, "DOWN") {
		t.Errorf("list:\n%s", out)
	}
	_, out, _ = runCLI(t, "uptime", "add", "https://example.com")
	if !strings.Contains(out, "Paused on the free plan until the team adds credit.") || strings.Contains(out, "every minute") {
		t.Errorf("add: %q", out)
	}
	// A paused check's old state is not something that needs you now.
	_, out, _ = runCLI(t)
	if strings.Contains(out, "Shop is not answering") {
		t.Errorf("now:\n%s", out)
	}
}

func TestErrorsSuggestsTheSnippetOnlyWhenItHelps(t *testing.T) {
	none := reply(200, `{"today":{"errors":0,"groups":0,"frontends":[]},"groups":[]}`)
	signInOver(t, routes{"/v1/browser/errors": none})
	_, out, _ := runCLI(t, "errors", "--frontend", "storefront-web")
	if !strings.Contains(out, "Last 24 hours: 0 errors") || strings.Contains(out, "snippet") {
		t.Errorf("a reporting frontend:\n%s", out)
	}
	owner := reply(200, `{"role":{"id":"owner","name":"Owner"},"levels":{"settings":"manage"},"switches":{},"canSee":"Everything","endsAt":null,"team":"Acme"}`)
	signInOver(t, routes{"/v1/browser/errors": none, "/v1/frontends": reply(200, `{"frontends":[]}`), "/v1/me/access": owner})
	if _, out, _ = runCLI(t, "errors"); !strings.Contains(out, "Add the snippet to one: Settings, Frontends.") {
		t.Errorf("no frontend, owner:\n%s", out)
	}
	signInOver(t, routes{"/v1/browser/errors": none, "/v1/frontends": reply(200, `{"frontends":[]}`), "/v1/me/access": viewOnly})
	if _, out, _ = runCLI(t, "errors"); strings.Contains(out, "snippet") {
		t.Errorf("no frontend, cannot add one:\n%s", out)
	}
}

func TestWatchDoesNotSayEveryCheckPassedWithoutAScan(t *testing.T) {
	for _, s := range []struct {
		srv  api.Server
		want string
	}{
		{api.Server{ID: "s9", Name: "new"}, "Not scanned yet."},
		{api.Server{ID: "s8", Name: "shop-app", Kind: "managed"}, "A managed service: Kiyesi does not scan it."},
	} {
		m := watchModel{ctx: context.Background(), c: api.New("http://127.0.0.1:1", ""), clock: time.Now}
		m.data.servers = []api.Server{s.srv}
		d := m.open()().(watchDetail)
		got := strings.Join(d.lines, "\n")
		if !strings.Contains(got, s.want) || strings.Contains(got, "every check passed") {
			t.Errorf("%s: %q", s.srv.Name, got)
		}
	}
}

func writeMap(t *testing.T, dir, name string, size int) string {
	t.Helper()
	p := filepath.Join(dir, name)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(`{"version":3,"mappings":"`+strings.Repeat("A", size)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// --delete prints the command that removes only the maps the service has:
// a skipped one is never in it. Kiyesi itself deletes nothing.
func TestSourcemapsDeleteNamesOnlyTheMapsThatWereSent(t *testing.T) {
	t.Setenv("KIYESI_ETC", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }))
	t.Cleanup(srv.Close)
	token := []string{"KIYESI_DEPLOY_TOKEN=kdp_" + strings.Repeat("a", 43)}

	dist := t.TempDir()
	big := writeMap(t, dist, "assets/big.js.map", maxMap+1)
	small := writeMap(t, dist, "assets/small.js.map", 10)
	code, out, errOut := runCLIEnv(t, token, "sourcemaps", "upload", "--version", "1", "--delete", "--api", srv.URL, dist)
	if code != ExitOK || !strings.Contains(out, "Uploaded 1 source map") || !strings.Contains(out, "Skipped 1 larger than 20 MB, still in the folder") {
		t.Errorf("mixed: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(out, "  rm "+small) || strings.Contains(out, big) {
		t.Errorf("the command should name the sent map only: %q", out)
	}
	for _, f := range []string{small, big} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was deleted", f)
		}
	}

	// Nothing sent: no command, and not a success.
	only := t.TempDir()
	writeMap(t, only, "assets/big.js.map", maxMap+1)
	code, out, errOut = runCLIEnv(t, token, "sourcemaps", "upload", "--version", "1", "--delete", "--api", srv.URL, only)
	if code != ExitUsage || strings.Contains(out, "Uploaded") || strings.Contains(out, "rm ") || !strings.Contains(errOut, "No source maps were uploaded") {
		t.Errorf("none sent: %d %q %q", code, out, errOut)
	}
}

func TestSourcemapsOnAConnectedServerUseThePersonNotTheServerToken(t *testing.T) {
	var mu sync.Mutex
	var auth string
	srv := signInOver(t, routes{"PUT /v1/sourcemaps": func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}})
	t.Setenv("KIYESI_ETC", t.TempDir())
	if err := saveConnection(srv.URL, "s1", "ksv_server_token"); err != nil {
		t.Fatal(err)
	}
	dist := t.TempDir()
	writeMap(t, dist, "a.js.map", 10)
	code, out, errOut := runCLIEnv(t, nil, "sourcemaps", "upload", "--version", "1", dist)
	mu.Lock()
	defer mu.Unlock()
	if code != ExitOK || auth != "Bearer "+personToken {
		t.Errorf("%d %q %q sent with %q", code, out, errOut, auth)
	}
}
