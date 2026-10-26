package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

// signInWith signs in to a service made of routes: path to answer.
// Anything else is a 404, as from the service.
func signInWith(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) {
	t.Helper()
	t.Setenv("KIYESI_CONFIG", t.TempDir())
	keychain = noKeychain{}
	listFilter.project, listFilter.env = "", ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"Not found."}`))
	}))
	t.Cleanup(srv.Close)
	if _, err := saveLogin(srv.URL, "tok", ""); err != nil {
		t.Fatal(err)
	}
}

func say(body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func sayStatus(code int, body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

const oneServer = `{"servers":[{"id":"s1","name":"web","connected":true,"state":"connected"}]}`

func TestAPIErrMapsEachAnswerToItsExitCode(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		code int
		msg  string
	}{
		{"area hidden", &api.NotFoundError{Message: "Not found.", Area: "metrics"}, ExitNoAccess, "Your role cannot see Metrics"},
		{"area hidden, unknown name", &api.NotFoundError{Message: "Not found.", Area: "new_area"}, ExitNoAccess, "Your role cannot see this"},
		{"not there", &api.NotFoundError{Message: "Not found."}, ExitUsage, "Not found."},
		{"not there, in words", &api.NotFoundError{Message: `There is no project "X".`}, ExitUsage, `There is no project "X".`},
		{"bad request", &api.Problem{Status: 400, Message: "Say how long."}, ExitUsage, "Say how long."},
		{"clash", &api.Problem{Status: 409, Message: "There is already a server called web."}, ExitUsage, "There is already a server called web."},
		{"unprocessable", &api.Problem{Status: 422, Message: "That cannot be done."}, ExitUsage, "That cannot be done."},
		{"signed out", api.ErrSignedOut, ExitNoAccess, "kiyesi login"},
		{"not allowed", &api.Problem{Status: 403, Code: "not_allowed", Message: "Your role does not allow this."}, ExitNoAccess, "Your role does not allow this."},
		{"service failed", &api.Problem{Status: 500, Message: "Something went wrong on our side."}, ExitNoAccess, "Something went wrong"},
		{"cannot reach", errors.New("cannot reach https://api.example.com: refused"), ExitNoAccess, "cannot reach"},
	} {
		var e *exitError
		if !errors.As(apiErr(c.err), &e) || e.code != c.code || !strings.Contains(e.msg, c.msg) {
			t.Errorf("%s: got %+v, want %d %q", c.name, e, c.code, c.msg)
		}
	}
	if apiErr(nil) != nil {
		t.Error("no error is no error")
	}
}

func TestAHiddenAreaSaysTheRoleIsWhyNotThatTheServerIsMissing(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/servers":            say(oneServer),
		"/v1/servers/s1/metrics": sayStatus(404, `{"error":"not_found","message":"Not found.","area":"metrics"}`),
	})
	code, _, errOut := runCLI(t, "metrics", "web")
	if code != ExitNoAccess || !strings.Contains(errOut, "Your role cannot see Metrics") {
		t.Errorf("%d %q", code, errOut)
	}
}

func TestTheFreePlanSaysWhyThereAreNoMetricsLogsOrTraces(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/servers":            say(oneServer),
		"/v1/credit/banner":      say(`{"free":true,"banner":{"level":"free"}}`),
		"/v1/servers/s1/metrics": say(`{"step":60,"cpu":[],"memory":[],"disk":{},"requests":[],"errors":[],"p95":[],"deploys":[]}`),
		"/v1/logs":               say(`{"lines":[],"more":false,"notice":"over_allowance"}`),
		"/v1/logs/export":        say(``),
		"/v1/traces":             say(`{"traces":[]}`),
	})
	for _, args := range [][]string{{"metrics", "web"}, {"logs"}, {"traces"}} {
		code, out, errOut := runCLI(t, args...)
		if code != ExitOK || !strings.Contains(out, freePlanNote) {
			t.Errorf("%v: %d %q", args, code, out)
		}
		for _, wrong := range []string{"no data yet", "none read yet", "No lines match", "No slow or failed", "over today's log allowance"} {
			if strings.Contains(out+errOut, wrong) {
				t.Errorf("%v says %q:\n%s%s", args, wrong, out, errOut)
			}
		}
	}
	path := filepath.Join(t.TempDir(), "x.jsonl")
	code, out, _ := runCLI(t, "logs", "--output", path)
	if code != ExitOK || !strings.Contains(out, freePlanNote) || strings.Contains(out, "Saved") {
		t.Errorf("export: %d %q", code, out)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("an empty file was saved")
	}
}

func TestAPaidTeamStillSeesItsEmptyStates(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/credit/banner": say(`{"free":false,"banner":null}`),
		"/v1/logs":          say(`{"lines":[],"more":false,"notice":"over_allowance"}`),
	})
	code, out, errOut := runCLI(t, "logs")
	if code != ExitOK || !strings.Contains(out, "No lines match") || !strings.Contains(errOut, "over today's log allowance") {
		t.Errorf("%d %q %q", code, out, errOut)
	}
}

func TestAServerNotWatchedOnTheFreePlanSaysSo(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/servers":    say(`{"servers":[{"id":"s1","name":"web","connected":true,"state":"connected","covered":false}]}`),
		"/v1/servers/s1": say(`{"server":{"id":"s1","name":"web","covered":false},"report":null,"reportAt":null}`),
	})
	code, out, _ := runCLI(t, "server", "web")
	if code != ExitOK || !strings.Contains(out, "Not watched on the free plan") || !strings.Contains(out, "kiyesi credit topup") || strings.Contains(out, "within a minute") {
		t.Errorf("%d %q", code, out)
	}
}

func TestOldUsageIsNeverShownAsCurrent(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	v := 31.0
	no, yes := false, true
	mk := func(age time.Duration, state string, covered, fresh *bool) api.Server {
		s := api.Server{State: state, Covered: covered, MetricsFresh: fresh}
		s.LastMetrics = &struct {
			At     time.Time `json:"at"`
			CPU    *float64  `json:"cpu"`
			Memory *float64  `json:"memory"`
			Disk   *float64  `json:"disk"`
		}{At: now.Add(-age), CPU: &v, Memory: &v, Disk: &v}
		return s
	}
	for _, c := range []struct {
		name string
		s    api.Server
		want string
	}{
		{"a minute old", mk(time.Minute, "connected", nil, nil), "31%"},
		{"an hour old", mk(time.Hour, "connected", nil, nil), "-"},
		{"disconnected", mk(time.Minute, "disconnected", nil, nil), "-"},
		{"not watched", mk(time.Minute, "connected", &no, nil), "-"},
		{"the service says old", mk(time.Minute, "connected", nil, &no), "-"},
		{"the service says current", mk(time.Hour, "connected", nil, &yes), "31%"},
	} {
		cpu, mem, disk := usage(c.s, now)
		if cpu != c.want || mem != c.want || disk != c.want {
			t.Errorf("%s: %s %s %s, want %s", c.name, cpu, mem, disk, c.want)
		}
	}
}

func TestSeenSaysJustNowThenSecondsThenMinutes(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) api.Server {
		t := now.Add(-d)
		return api.Server{Connected: true, State: "connected", LastSeenAt: &t}
	}
	for d, want := range map[time.Duration]string{
		0: "just now", 5 * time.Second: "just now", 30 * time.Second: "30 s ago",
		119 * time.Second: "1 min ago", 2 * time.Minute: "2 min ago", 3 * time.Hour: "3 h ago",
	} {
		if got := seen(at(d), now); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

func TestEmptyFindingsSayWhy(t *testing.T) {
	scanned := api.Server{Name: "web", Kind: "server", LastScan: &api.Summary{}}
	withWarnings := scanned
	withWarnings.LastScan = &api.Summary{}
	withWarnings.LastScan.Counts.Warnings = 2
	managed := api.Server{Name: "shop", Kind: "managed"}
	fresh := api.Server{Name: "new-box", Kind: "server"}
	for _, c := range []struct {
		name     string
		servers  []api.Server
		severity string
		named    bool
		want     string
	}{
		{"no servers", nil, "", false, "No servers yet"},
		{"only managed", []api.Server{managed}, "", false, "Only managed services here"},
		{"a managed one, named", []api.Server{managed}, "", true, "shop is a managed service"},
		{"never scanned, named", []api.Server{fresh}, "", true, "new-box has not sent a scan yet"},
		{"none scanned", []api.Server{fresh}, "", false, "No server has sent a scan yet"},
		{"hidden by severity", []api.Server{withWarnings}, "critical", false, "No critical findings on the latest scans. Run kiyesi findings without --severity for the rest."},
		{"none at that severity", []api.Server{scanned}, "critical", false, "No critical findings on the latest scans."},
		{"some not scanned", []api.Server{scanned, fresh}, "", false, "1 server has not sent a scan yet."},
		{"all passed", []api.Server{scanned}, "", false, "every check passed"},
	} {
		if got := noFindings(c.servers, c.severity, c.named); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// kiyesi findings gives only the commands a person reviews and runs, never
// kiyesi fix, even when the service still has a finding an agent before
// 0.40.0 named one for; the help says Kiyesi never changes a server.
func TestFindingsNeverOfferKiyesiFix(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/findings": say(`{"findings":[{"server":{"id":"s1","name":"web"},"check":"ssh","checkName":"SSH settings","severity":"warning","sentence":"SSH allows password login","why":"w","fix":"edit sshd_config","autoFix":"ssh-password","scannedAt":"2026-10-20T10:00:00Z"}]}`),
	})
	code, out, _ := runCLI(t, "findings")
	if code != ExitOK || !strings.Contains(out, "Fix:\n            edit sshd_config\n") || strings.Contains(out, "kiyesi fix") {
		t.Errorf("%d %q", code, out)
	}
	_, help, _ := runCLI(t, "findings", "--help")
	if !strings.Contains(help, "Kiyesi never changes a server") || strings.Contains(help, "sudo kiyesi fix") {
		t.Errorf("help: %s", help)
	}
}

func TestCreditAtZeroDoesNotContradictItself(t *testing.T) {
	never := `{"live":true,"balance":0,"daysLeft":0,"usedLastWeek":0,"runsOutOn":"2026-10-20T00:00:00Z","state":{"storing":false,"readOnly":false,"eraseOn":null},"bundles":[],"lines":[]}`
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/credit": say(never)})
	code, out, _ := runCLI(t, "credit")
	if code != ExitOK || !strings.Contains(out, "Balance: 0 server-days") || !strings.Contains(out, "free plan") {
		t.Fatalf("%d %q", code, out)
	}
	for _, wrong := range []string{"does not run out", "days left", "deleted on"} {
		if strings.Contains(out, wrong) {
			t.Errorf("says %q:\n%s", wrong, out)
		}
	}
	ranOut := strings.Replace(never, `"eraseOn":null`, `"eraseOn":"2026-11-19T00:00:00Z"`, 1)
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/credit": say(ranOut)})
	if _, out, _ := runCLI(t, "credit"); !strings.Contains(out, "Stored history is deleted on 19 Nov 2026") {
		t.Errorf("ran out: %q", out)
	}
	one := `{"live":true,"balance":5,"daysLeft":35,"usedLastWeek":1,"runsOutOn":"2026-11-24T00:00:00Z","state":{"storing":true,"readOnly":false,"eraseOn":null},"bundles":[],"lines":[]}`
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/credit": say(one)})
	if _, out, _ := runCLI(t, "credit"); !strings.Contains(out, "at the 1 server-day used in the last week") {
		t.Errorf("one used: %q", out)
	}
}

func TestRenewalsCountCalendarDays(t *testing.T) {
	for _, c := range []struct {
		days   int
		ranOut bool
		want   string
	}{
		{5, false, "in 5 days"}, {1, false, "tomorrow"}, {0, false, "today"}, {0, true, "ran out today"},
		{-1, true, "ran out yesterday"}, {-3, true, "ran out 3 days ago"},
	} {
		if got := daysWords(c.days, c.ranOut); got != c.want {
			t.Errorf("%d %v: %q, want %q", c.days, c.ranOut, got, c.want)
		}
	}
}

func TestDatabasesShowTheReadErrorBackupAndFullOn(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/databases": say(`{"databases":[{"id":"d1","name":"orders","label":"PostgreSQL 16","where":"server","server":{"name":"db"},"newestBackupAt":"` + time.Now().Add(-3*time.Hour).UTC().Format(time.RFC3339) + `","fullAt":"2026-12-01T00:00:00Z","error":null,"status":"ok","problems":[]},{"id":"d2","name":"sessions","label":"Redis","where":"server","server":{"name":"db"},"error":"It refused the connection.","status":"ok","problems":[]}]}`),
	})
	code, out, _ := runCLI(t, "databases")
	for _, want := range []string{"NEWEST BACKUP", "FULL ON", "3 h ago", "1 Dec 2026", "sessions cannot be read: It refused the connection.", "NEEDS ATTENTION"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q (exit %d):\n%s", want, code, out)
		}
	}
}

func TestAdvisoriesSayWhichServerWasNotChecked(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/advisories": say(`{"checkedAt":"2026-10-20T10:00:00Z","advisories":[],"errors":[{"serverId":"s2","serverName":"db","message":"endoflife.date is not answering"}]}`),
	})
	code, out, _ := runCLI(t, "advisories")
	if code != ExitOK || !strings.Contains(out, "Not checked on db: endoflife.date is not answering") || strings.Contains(out, "everything is supported and patched") {
		t.Errorf("%d %q", code, out)
	}
}

func TestDatamapSaysWhereTheHomeCountryCameFrom(t *testing.T) {
	row := `"rows":[{"serverId":"s1","serverName":"web","kind":"server","name":"web","confidence":"confirmed","result":"inside"}]`
	for _, c := range []struct{ body, want string }{
		{`{"home":{"code":"GB","name":"United Kingdom","chosen":false},"counts":{"mapped":1},` + row + `}`, "Home country: United Kingdom (from the agents' settings)."},
		{`{"home":null,"counts":{"mapped":1},` + row + `}`, "Choose a home country in the dashboard, Data map, to compare against."},
		{`{"home":null,"counts":{},"rows":[]}`, "Nothing is mapped yet. Each connected server's next scan adds its rows."},
	} {
		signInWith(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/data-map": say(c.body)})
		if code, out, _ := runCLI(t, "datamap"); code != ExitOK || !strings.Contains(out, c.want) {
			t.Errorf("%d %q, want %q", code, out, c.want)
		}
	}
}

func TestCostsNameNoSingleCountrysCurrency(t *testing.T) {
	_, help, _ := runCLI(t, "costs", "--help")
	if strings.Contains(help, "NGN") || !strings.Contains(help, "EUR") {
		t.Errorf("help: %s", help)
	}
	signInWith(t, nil)
	if code, _, errOut := runCLI(t, "costs", "--currency", "euro"); code != ExitUsage || strings.Contains(errOut, "NGN") || !strings.Contains(errOut, "EUR, GBP or USD") {
		t.Errorf("%d %q", code, errOut)
	}
}

func TestNothingChangedIsNotReportedAsAChange(t *testing.T) {
	called := 0
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/servers": say(`{"servers":[{"id":"s1","name":"web-1","connected":false,"state":"disconnected"}]}`),
		"/v1/servers/s1": func(w http.ResponseWriter, _ *http.Request) {
			called++
			w.WriteHeader(http.StatusNoContent)
		},
		"/v1/servers/s1/disconnect": func(w http.ResponseWriter, _ *http.Request) {
			called++
			w.WriteHeader(http.StatusNoContent)
		},
		"/v1/servers/deleted":    say(`{"servers":[{"id":"d1","name":"old","deletedAt":"2026-10-19T10:00:00Z","purgeAt":"2026-10-26T10:00:00Z"}]}`),
		"/v1/servers/d1/restore": sayStatus(409, `{"error":"bad_request","message":"There is already a server called old."}`),
	})
	if code, out, _ := runCLI(t, "servers", "rename", "WEB-1", "web-1"); code != ExitOK || !strings.Contains(out, "web-1 is already called that.") {
		t.Errorf("rename: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, "servers", "disconnect", "web-1"); code != ExitOK || !strings.Contains(out, "web-1 is already disconnected") {
		t.Errorf("disconnect: %d %q", code, out)
	}
	if called != 0 {
		t.Errorf("%d changes were asked for", called)
	}
	if code, _, errOut := runCLI(t, "servers", "restore", "old"); code != ExitUsage || !strings.Contains(errOut, "There is already a server called old.") {
		t.Errorf("restore clash: %d %q", code, errOut)
	}
}

func TestAnEmptyFilteredListSaysSo(t *testing.T) {
	signInWith(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/servers": say(`{"servers":[]}`)})
	for args, want := range map[string]string{
		"servers --project Shop":               "No servers in that project.",
		"servers --env staging":                "No servers in that environment.",
		"servers --project Shop --env staging": "No servers in that project and environment.",
		"servers":                              "No servers yet.",
	} {
		listFilter.project, listFilter.env = "", ""
		code, out, _ := runCLI(t, strings.Fields(args)...)
		if code != ExitOK || !strings.Contains(out, want) {
			t.Errorf("%s: %d %q", args, code, out)
		}
	}
	listFilter.project, listFilter.env = "", ""
}

func TestPlatformsMentionWaitingServicesOnlyWhenSomeWait(t *testing.T) {
	link := `{"links":[{"id":"l1","name":"shop","platform":"render","project":{"name":"Shop"},"environment":"production","services":[{"name":"api","state":"connected"}],"waiting":%s}]}`
	for waiting, want := range map[string]bool{`[]`: false, `["worker"]`: true} {
		signInWith(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/platform-links": say(strings.Replace(link, "%s", waiting, 1))})
		code, out, errOut := runCLI(t, "platforms")
		if code != ExitOK {
			t.Fatalf("%d %s", code, errOut)
		}
		if got := strings.Contains(out, "Services that wait"); got != want {
			t.Errorf("waiting %s: %q", waiting, out)
		}
	}
}
