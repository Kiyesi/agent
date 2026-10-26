package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

// What the fake API last got for /v1/logs, how many Follow asks it
// answered, and the server changes it was asked for.
var (
	serverCalls   []string
	lastLogsQuery url.Values
	followPolls   atomic.Int32
	// lastLogsMu guards lastLogsQuery: the fake server writes it from its
	// own goroutine while a test reads it.
	lastLogsMu sync.Mutex
)

func setLastLogsQuery(q url.Values) {
	lastLogsMu.Lock()
	defer lastLogsMu.Unlock()
	lastLogsQuery = q
}

func lastLogs() url.Values {
	lastLogsMu.Lock()
	defer lastLogsMu.Unlock()
	return lastLogsQuery
}

const personToken = "session-token-for-tests"

// creditBody, when set, is what the fake API answers for /v1/credit.
var creditBody string

// signOuts is the token of each sign-out the fake API was asked for.
var signOuts []string

// noKeychain makes the token go to the file, as on a server.
type noKeychain struct{}

func (noKeychain) available() bool            { return false }
func (noKeychain) set(string, string) error   { return nil }
func (noKeychain) get(string) (string, error) { return "", nil }
func (noKeychain) remove(string) error        { return nil }

// fakeAPI answers the sign-in and the servers routes like the service.
// apiRequests counts the signed-in requests the fake API answered.
var apiRequests atomic.Int32

// lastFilter is the --project and --env headers of the latest request.
var (
	lastFilterMu sync.Mutex
	lastFilter   [2]string
)

func setLastFilter(project, env string) {
	lastFilterMu.Lock()
	defer lastFilterMu.Unlock()
	lastFilter = [2]string{project, env}
}

func getLastFilter() [2]string {
	lastFilterMu.Lock()
	defer lastFilterMu.Unlock()
	return lastFilter
}

func fakeAPI(t *testing.T, pendingPolls int32) *httptest.Server {
	t.Helper()
	report, err := os.ReadFile("../render/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/auth/device/code":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["client_id"] != "kiyesi-cli" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"device_code":"dev","user_code":"ABCD-EFGH","verification_uri":"https://app.kiyesi.dev/device","verification_uri_complete":"https://app.kiyesi.dev/device?user_code=ABCD-EFGH","expires_in":600,"interval":5}`))
			return
		case "/api/auth/device/token":
			if polls.Add(1) <= pendingPolls {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending","error_description":"waiting"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + personToken + `","token_type":"Bearer"}`))
			return
		case "/api/auth/sign-out":
			signOuts = append(signOuts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if r.Header.Get("Authorization") == "Bearer broken-token" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		if r.URL.Path == "/v1/preflight" && (r.Header.Get("Authorization") == "Bearer "+personToken || r.Header.Get("Authorization") == "Bearer kdp_preflight") {
			setLastLogsQuery(r.URL.Query())
			if r.URL.Query().Get("server") == "calm-box" {
				_, _ = w.Write([]byte(`{"server":{"id":"s3","name":"calm-box","project":null,"environment":null},"answer":"go","checks":[{"id":"memory","label":"Memory","status":"pass","sentence":"41% used."}],"doFirst":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"server":{"id":"s1","name":"checkout-api-prod","project":{"name":"Checkout"},"environment":"production"},"answer":"wait","checks":[{"id":"memory","label":"Memory","status":"wait","sentence":"93% used. The app was killed at 10:41 today."},{"id":"disk","label":"Disk","status":"pass","sentence":"64% used."},{"id":"backup","label":"Backup","status":"wait","sentence":"Newest backup is 31 hours old."},{"id":"certificate","label":"Certificate","status":"pass","sentence":"Valid for 9 more days."},{"id":"incident","label":"Open incident","status":"wait","sentence":"INC-12 Checkout API returning 502 errors."},{"id":"deploy","label":"Last deploy","status":"pass","sentence":"checkout-api 3.8.1 was healthy."}],"doFirst":["Add swap or move up a size, then mark the incident it caused fixed","Find out why the backup did not run, and run it","Fix INC-12 first, or deploy the fix it needs"],"scannedAt":"2026-10-13T10:00:00Z"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+personToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"signed_out","message":"Sign in to continue."}`))
			return
		}
		seen := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339)
		setLastFilter(r.Header.Get("X-Kiyesi-Project"), r.Header.Get("X-Kiyesi-Env"))
		apiRequests.Add(1)
		switch r.URL.Path {
		case "/v1/drills", "/v1/drills/latest":
			if r.Method == http.MethodPost && r.Header.Get("X-Kiyesi-Team") == "bbbbbbbbbbbbbbbbbbbbbbbb" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not_found","message":"Not found."}`))
				return
			}
			_, _ = w.Write([]byte(`{"drill":{"id":"d1","startedAt":"2026-10-13T10:00:00Z","startedBy":"Ada Obi","done":true,"summary":"1 of 2 steps reached a person. Ada Obi's Telegram did not deliver: the bot is no longer in your chat. In a real incident, this person would not have been told.","steps":[{"step":1,"name":"Ifeoma Nwosu","realMinutes":15,"sentAt":"2026-10-13T10:00:01Z","via":"Slack","delivered":true,"reason":null,"deliveredInSeconds":2,"ackedInMinutes":1},{"step":2,"name":"Ada Obi","realMinutes":30,"sentAt":"2026-10-13T10:01:01Z","via":"Telegram","delivered":false,"reason":"the bot is no longer in your chat","deliveredInSeconds":1,"ackedInMinutes":null}]}}`))
		case "/v1/servers/s1/passport":
			_, _ = w.Write([]byte(`{"server":"checkout-api-prod","label":"13 October 2026","note":{"text":"Runs the checkout API for the Checkout project.","by":"Ada Obi"},"runs":[{"name":"checkout-checkout-api-1","image":"checkout-api:3.8.1","restart":"docker compose restart checkout-api"}],"ports":[{"port":"80, 443","what":"Allowed in the agent's settings.","status":"expected"},{"port":"6379","what":"Redis is open to the internet on port 6379.","status":"close"}],"jobs":[{"name":"renew-certificates","schedule":"Every day at 03:00","status":"Failed on its last run."}],"usual":[{"title":"Go back to the version before","command":"IMAGE_TAG=3.8.0 docker compose up -d checkout-api"}],"facts":[["Project","Checkout, production"],["Cost","USD 6 a month"]],"people":[["On call","Ifeoma Nwosu"]],"dependsOn":[{"name":"checkout-db-prod:5432","what":"Database, in London, UK"}],"changes":[{"at":"2026-10-13T10:41:00Z","text":"checkout-api was killed for using too much memory."}]}`))
		case "/v1/servers/s1/passport/pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.7 passport"))
		case "/v1/servers/s1/badge":
			if r.Method == http.MethodDelete {
				// In Globex the badge was never on.
				if r.Header.Get("X-Kiyesi-Team") == "bbbbbbbbbbbbbbbbbbbbbbbb" {
					_, _ = w.Write([]byte(`{"wasOn":false}`))
					return
				}
				_, _ = w.Write([]byte(`{"wasOn":true}`))
				return
			}
			_, _ = w.Write([]byte(`{"badge":{"url":"https://api.kiyesi.dev/v1/public/badge/AAAAAAAAAAAAAAAAAAAAAAAA.svg","markdown":"[![Kiyesi grade](https://api.kiyesi.dev/v1/public/badge/AAAAAAAAAAAAAAAAAAAAAAAA.svg)](https://kiyesi.dev)"}}`))
		case "/v1/servers/s2/badge":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","message":"Your role cannot manage this server."}`))
		case "/v1/servers/s1/passport/share":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"url":"https://reports.kiyesi.dev/r/abc","expiresAt":"2026-10-20T11:00:00Z"}`))
		case "/v1/findings":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"findings":[{"server":{"id":"s1","name":"checkout-api-prod"},"check":"exposed-databases","checkName":"Exposed databases","severity":"critical","confidence":"likely","sentence":"Redis is open to the internet on port 6379","why":"Anyone can connect and read or wipe the data.","fix":"bind the port to 127.0.0.1 in docker-compose.yml, then\ndocker compose up -d redis","scannedAt":"` + seen + `"},{"server":{"id":"s1","name":"checkout-api-prod"},"check":"ssh","checkName":"SSH settings","severity":"warning","confidence":null,"sentence":"SSH allows password login","why":"Passwords can be guessed by automated attacks.","fix":"echo \"PasswordAuthentication no\" | sudo tee /etc/ssh/sshd_config.d/00-kiyesi.conf","scannedAt":"` + seen + `"}]}`))
		case "/v1/me":
			// Two teams: Acme by default, Globex when chosen.
			team, role := `{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","name":"Acme"}`, "owner"
			if r.Header.Get("X-Kiyesi-Team") == "bbbbbbbbbbbbbbbbbbbbbbbb" {
				team, role = `{"id":"bbbbbbbbbbbbbbbbbbbbbbbb","name":"Globex"}`, "viewer"
			}
			_, _ = w.Write([]byte(`{"user":{"name":"Ada","email":"ada@example.com"},"team":` + team + `,"role":"` + role + `","teams":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","name":"Acme","roleName":"Owner"},{"id":"bbbbbbbbbbbbbbbbbbbbbbbb","name":"Globex","roleName":"Viewer"}]}`))
		case "/v1/servers":
			_, _ = w.Write([]byte(`{"servers":[{"id":"s1","name":"checkout-api-prod","project":{"id":"p","name":"Shop"},"environment":"production","connected":true,"lastSeenAt":"` + seen + `","silent":false,"lastMetrics":{"cpu":31.5,"memory":52,"disk":30},"lastScan":{"at":"` + seen + `","grade":{"score":55,"letter":"D","basedOn":22,"total":22},"counts":{"critical":2,"warnings":3,"passed":17,"skipped":0}},"calm":{"since":null,"days":0}},{"id":"s2","name":"new-box","connected":false,"silent":false}]}`))
		case "/v1/servers/s1":
			if r.Method == http.MethodPatch {
				var in map[string]string
				_ = json.NewDecoder(r.Body).Decode(&in)
				if in["name"] == "web 2" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"A server name uses letters, digits, dots, dashes and underscores, up to 63 characters."}`))
					return
				}
				serverCalls = append(serverCalls, "rename s1 "+in["name"])
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.Method == http.MethodDelete {
				var in map[string]string
				_ = json.NewDecoder(r.Body).Decode(&in)
				serverCalls = append(serverCalls, "delete "+in["name"]+" "+in["twoStepCode"])
				_, _ = w.Write([]byte(`{"purgeAt":"2026-10-17T10:00:00Z"}`))
				return
			}
			_, _ = w.Write([]byte(`{"server":{"id":"s1","name":"checkout-api-prod"},"report":` + string(report) + `,"reportAt":"` + seen + `"}`))
		case "/v1/servers/s2":
			_, _ = w.Write([]byte(`{"server":{"id":"s2","name":"new-box"},"report":null,"reportAt":null}`))
		case "/v1/alerts/channels":
			_, _ = w.Write([]byte(`{"channels":[{"id":"c1","kind":"slack","name":"#ops","linked":true,"detail":null},{"id":"c2","kind":"telegram","name":"Telegram (waiting)","linked":false,"detail":null}]}`))
		case "/v1/alerts/channels/c1/test":
			_, _ = w.Write([]byte(`{"sent":true}`))
		case "/v1/alerts":
			_, _ = w.Write([]byte(`{"alerts":[{"id":"a1","kind":"finding","subject":"checkout-api-prod","sentence":"Redis is open to the internet on port 6379","openedAt":"` + seen + `","ackedAt":null}]}`))
		case "/v1/servers/s1/mute":
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["for"] == "forever" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"Say how long, from 5 minutes to 7 days, such as 30m, 2h or 1d. Every mute ends."}`))
				return
			}
			_, _ = w.Write([]byte(`{"until":"2026-10-10T08:30:00Z"}`))
		case "/v1/uptime":
			if r.Method == http.MethodPost {
				var in map[string]string
				_ = json.NewDecoder(r.Body).Decode(&in)
				if strings.Contains(in["url"], "169.254") {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"That address is on a private network. Only public addresses can be checked from outside."}`))
					return
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"u2"}`))
				return
			}
			_, _ = w.Write([]byte(`{"checks":[{"id":"u1","name":"Shop","url":"https://shop.example.com","status":"down","last":{"at":"` + seen + `","ok":false,"status":null,"ms":null,"error":"no answer within 10 seconds"}}]}`))
		case "/v1/history":
			if r.URL.Query().Get("kind") == "deploy" {
				_, _ = w.Write([]byte(`{"events":[{"id":"1","at":"` + seen + `","kind":"deploy","title":"Deployed checkout-api 3.8.1 (by ada)"}]}`))
				return
			}
			if q := r.URL.Query(); q.Get("since") != "24h" || q.Get("server") != "s1" {
				_, _ = w.Write([]byte(`{"events":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"events":[{"id":"2","at":"` + seen + `","kind":"grade_changed","title":"checkout-api-prod: grade went from B 80 to A 95"},{"id":"1","at":"` + seen + `","kind":"deploy","title":"Deployed checkout-api 3.8.1 (by ada)"}]}`))
		case "/v1/servers/s1/disconnect":
			serverCalls = append(serverCalls, "disconnect")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/servers/s1/token":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["twoStepCode"] != "123456" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"two_step_failed","message":"That code is not right."}`))
				return
			}
			_, _ = w.Write([]byte(`{"command":"sudo kiyesi connect --token ksv_new"}`))
		case "/v1/servers/deleted":
			_, _ = w.Write([]byte(`{"servers":[{"id":"d1","name":"old-web-1","deletedAt":"2026-10-10T10:00:00Z","purgeAt":"2026-10-17T10:00:00Z"}]}`))
		case "/v1/servers/d1/restore":
			serverCalls = append(serverCalls, "restore d1")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/frontends":
			_, _ = w.Write([]byte(`{"frontends":[{"id":"f1","name":"storefront-web","sites":["https://shop.example.com"]}]}`))
		case "/v1/browser/errors":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"today":{"errors":214,"groups":1,"frontends":["storefront-web"]},"groups":[{"id":"g1","frontend":{"id":"f1","name":"storefront-web"},"kind":"error","type":"TypeError","message":"Cannot read properties of undefined (reading 'amount')","where":"src/components/CheckoutSummary.tsx:48","mapped":true,"events":214,"users":163,"firstSeen":{"at":"2026-10-10T09:09:00Z","version":"2.14.0"},"lastSeen":{"at":"2026-10-10T10:00:00Z","version":"2.14.0"}},{"id":"g2","frontend":{"id":"f1","name":"storefront-web"},"kind":"request","type":"Request failed","message":"POST /api/orders returned 502","where":"/assets/index-3f9a.js:1","mapped":false,"events":37,"users":null,"firstSeen":{"at":"2026-10-10T10:41:00Z","version":"2.14.0"},"lastSeen":{"at":"2026-10-10T10:41:00Z","version":"2.14.0"}}]}`))
		case "/v1/databases":
			_, _ = w.Write([]byte(`{"counts":{"watched":2},"databases":[{"id":"d1","name":"orders","label":"PostgreSQL 15.4","where":"server","server":{"name":"checkout-db-prod"},"sizeBytes":23085449216,"limitBytes":26843545600,"connections":61,"maxConnections":100,"slowLastHour":14,"status":"attention","problems":[{"kind":"filling","sentence":"At the rate it grew, storage is full in about 9 days (21.5 GB of 25 GB)."}]},{"id":"d2","name":"catalogue","label":"MongoDB 6","where":"hosted","server":{"name":"checkout-api-prod"},"sizeBytes":432013312,"limitBytes":536870912,"connections":null,"maxConnections":null,"slowLastHour":null,"status":"ok","problems":[]}]}`))
		case "/v1/status-pages":
			_, _ = w.Write([]byte(`{"pages":[{"id":"sp1","slug":"acme-status","title":"Acme status","url":"https://status.kiyesi.dev/acme-status","on":true,"subscribers":3,"viewsThisWeek":41,"components":[{"name":"Placing orders","status":"down"},{"name":"Payment page","status":"up"}]}]}`))
		case "/v1/status-pages/sp1/posts":
			_, _ = w.Write([]byte(`{"posts":[{"id":"p1","title":"Some orders are failing","resolvedAt":null,"entries":[]}]}`))
		case "/v1/status-pages/sp1/updates":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			body, _ := json.Marshal(in)
			serverCalls = append(serverCalls, "status "+string(body))
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"postId":"p1"}`))
		case "/v1/reports":
			if r.Method == http.MethodPost {
				var in map[string]string
				_ = json.NewDecoder(r.Body).Decode(&in)
				body, _ := json.Marshal(in)
				serverCalls = append(serverCalls, "report "+string(body))
				w.WriteHeader(http.StatusCreated)
				if in["kind"] == "datamap" {
					_, _ = w.Write([]byte(`{"id":"r2","kind":"datamap","period":"2026-10-12","title":"For an auditor, 12 October 2026","summary":"3 items mapped, 2 outside Nigeria.","madeAt":"2026-10-12T09:00:00Z","byKiyesi":false,"canShare":true,"canDownload":true}`))
					return
				}
				_, _ = w.Write([]byte(`{"id":"r1","kind":"monthly","period":"2026-09","title":"Checkout, September 2026","summary":"In September Checkout was available 99.94% of the time. Three incidents happened, and all were fixed.","madeAt":"2026-10-12T09:00:00Z","byKiyesi":false,"canShare":true,"canDownload":true}`))
				return
			}
			_, _ = w.Write([]byte(`{"reports":[{"id":"r0","kind":"monthly","period":"2026-08","title":"Checkout, August 2026","summary":"In August Checkout was available 100% of the time. No incidents happened.","madeAt":"2026-09-01T00:15:00Z","byKiyesi":true}],"projects":[{"id":"pc","name":"Checkout","firstFullMonth":"2026-08"}],"canMake":true,"printing":true}`))
		case "/v1/reports/r1/shares":
			var in map[string]int
			_ = json.NewDecoder(r.Body).Decode(&in)
			serverCalls = append(serverCalls, fmt.Sprintf("share r1 %d", in["days"]))
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"sh1","url":"https://reports.kiyesi.dev/` + strings.Repeat("t", 43) + `","expiresAt":"2026-10-19T09:00:00Z"}`))
		case "/v1/reports/r1/pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.7 report"))
		case "/v1/reports/r2/pdf":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"unavailable","message":"The PDF could not be made just now."}`))
		case "/v1/reports/r2":
			_, _ = w.Write([]byte(`{"html":"<!doctype html><title>Data map report</title>"}`))
		case "/v1/reports/card":
			_, _ = w.Write([]byte(`{"content":{"label":"Week of 5 October","caught":9,"fixed":8,"fixMinutes":38,"summary":"9 problems caught, eight fixed, typical time to fix 38 minutes."}}`))
		case "/v1/data-map":
			_, _ = w.Write([]byte(`{"home":{"code":"NG","name":"Nigeria","chosen":true},"counts":{"mapped":3,"outside":2,"inside":1,"review":0,"mustMove":1},"rows":[{"serverId":"s1","serverName":"checkout-api-prod","kind":"database","name":"orders:5432","provider":"DigitalOcean","place":"London, UK","country":"GB","confidence":"likely","payment":true,"managed":false,"result":"must_move"},{"serverId":"s1","serverName":"checkout-api-prod","kind":"server","name":"DigitalOcean, London, UK","provider":"DigitalOcean","place":"London, UK","country":"GB","confidence":"confirmed","payment":false,"managed":false,"result":"outside"},{"serverId":"s2","serverName":"storefront","kind":"server","name":"storefront","provider":"render","place":"Nigeria","country":"NG","confidence":"set","payment":false,"managed":true,"result":"inside"}],"ipinfo":true}`))
		case "/v1/servers/compare":
			if r.URL.Query().Get("a") != "s1" || r.URL.Query().Get("b") != "s2" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"a":{"id":"s1","name":"checkout-api-prod","read":true,"covered":true},"b":{"id":"s2","name":"new-box","read":true,"covered":true},"differences":3,"sections":[{"key":"system","rows":[],"same":3},{"key":"security","rows":[{"name":"ssh_password","a":"off","b":"on"}],"same":3},{"key":"packages","rows":[{"name":"openssl","a":"3.0.13-0ubuntu3.4","b":"3.0.13-0ubuntu3.1"},{"name":"redis-server","a":null,"b":"7.0.15"}],"same":412}]}`))
		case "/v1/tips":
			if r.URL.Query().Get("server") != "" && r.URL.Query().Get("server") != "s1" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"tips":[{"id":"memory-limit:checkout-api","sentence":"Set a memory limit on checkout-api","why":"With a limit, Docker restarts only this container.","fix":"docker update --memory 512m checkout-api","serverId":"s1","serverName":"checkout-api-prod"}]}`))
		case "/v1/advisories":
			_, _ = w.Write([]byte(`{"checkedAt":"` + seen + `","advisories":[{"kind":"end_of_life","level":"high","sentence":"Ubuntu 20.04 on this server stopped getting security fixes on 2025-05-31","why":"Flaws found from now on are not fixed for it.","fix":"sudo do-release-upgrade","firstSeenAt":"` + seen + `","serverId":"s1","serverName":"checkout-api-prod"}]}`))
		case "/v1/costs":
			if cur := r.URL.Query().Get("currency"); cur != "" {
				setLastLogsQuery(r.URL.Query())
				_, _ = w.Write([]byte(`{"currency":"` + cur + `","inCurrency":{"currency":"` + cur + `","monthly":83700,"save":37200,"notConverted":[]},"rate":{"day":"2026-10-13","source":"open.er-api.com"},"rateWarning":{"percent":8,"since":"2026-09-14","from":77500,"to":83700,"currency":"` + cur + `"},"totals":[{"currency":"USD","monthly":54,"save":24}],"servers":[{"server":{"name":"checkout-api-prod"},"size":"1 GB, 1 CPU","price":{"monthly":6,"currency":"USD"},"converted":{"monthly":9300,"currency":"` + cur + `"},"cpuPeak":58,"memoryPeak":91,"suggestion":{"kind":"too_small","sentence":"Move up to 2 GB.","change":6}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"totals":[{"currency":"USD","monthly":54,"save":24}],"servers":[{"server":{"name":"checkout-api-prod"},"size":"1 GB, 1 CPU","price":{"monthly":6,"currency":"USD"},"cpuPeak":58,"memoryPeak":91,"suggestion":{"kind":"too_small","sentence":"Move up to 2 GB. Its memory reached 91% at its busiest.","change":6}},{"server":{"name":"tools-01"},"size":"8 GB, 4 CPUs","price":{"monthly":48,"currency":"USD"},"cpuPeak":5,"memoryPeak":18,"suggestion":{"kind":"larger","sentence":"4 GB is enough, even at its busiest (CPU 5%, memory 18%).","change":-24}},{"server":{"name":"brand-new"},"size":"2 GB, 1 CPU","price":null,"cpuPeak":3,"memoryPeak":10,"suggestion":{"kind":"too_early","sentence":"Needs a week of figures to judge its size: 2 days so far.","change":null}}]}`))
		case "/v1/deploys":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"deploys":[{"id":"d2","app":"storefront-web","version":"2.14.0","by":"Tunde B.","at":"2026-10-10T09:05:00Z","server":{"id":"s1","name":"checkout-api-prod"},"status":"roll_back","sentence":"Watched for 10 minutes after it went out. Browser errors went from none to 25, all on the new version.","evidence":[],"rollback":"IMAGE_TAG=2.13.4 docker compose up -d storefront-web","decidedAt":"2026-10-10T09:15:00Z"},{"id":"d1","app":"checkout-api","version":"3.8.1","by":"ada","at":"2026-10-09T16:20:00Z","server":{"id":"s2","name":"storefront-web-prod"},"status":"healthy","sentence":"Watched for 10 minutes after it went out.","evidence":[],"rollback":null,"decidedAt":"2026-10-09T16:30:00Z"}]}`))
		case "/v1/expiries":
			_, _ = w.Write([]byte(`{"expiries":[{"id":"e1","kind":"certificate","name":"shop.example.com","expiresAt":"2026-10-20T00:00:00Z","daysLeft":4,"source":"tls","detail":"Let's Encrypt","needsDate":false},{"id":"e2","kind":"domain","name":"shop.com.ng","expiresAt":null,"daysLeft":null,"source":"rdap","detail":null,"needsDate":true}]}`))
		case "/v1/jobs":
			_, _ = w.Write([]byte(`{"counts":{"watched":2,"failedOrMissed":1,"long":0},"jobs":[{"id":"j1","name":"nightly-backup","server":{"id":"s1","name":"checkout-db-prod"},"schedule":{"source":"cron","text":"0 4 * * *","words":"Every day at 04:00"},"lastRun":{"runId":"r1","startedAt":"2026-10-07T04:00:00Z","endedAt":"2026-10-07T04:03:12Z","exitCode":0,"durationMs":192000},"running":null,"usualMs":190000,"nextExpected":"2026-10-08T04:00:00Z","status":"missed","problem":{"kind":"missed","at":"2026-10-08T04:05:00Z","text":"nightly-backup did not run when it was expected"}},{"id":"j2","name":"send-order-emails","server":{"id":"s2","name":"checkout-api-prod"},"schedule":{"source":"cron","text":"*/5 * * * *","words":"Every 5 minutes"},"lastRun":{"runId":"e1","startedAt":"2026-10-08T11:00:00Z","endedAt":"2026-10-08T11:00:48Z","exitCode":0,"durationMs":48000},"running":null,"usualMs":6000,"nextExpected":"2026-10-08T11:05:00Z","status":"on_time","problem":null}]}`))
		case "/v1/jobs/j1":
			_, _ = w.Write([]byte(`{"id":"j1","name":"nightly-backup","server":{"id":"s1","name":"checkout-db-prod"},"status":"missed","problem":{"kind":"missed","at":"2026-10-08T04:05:00Z","text":"nightly-backup did not run when it was expected"},"runs":[{"runId":"r0","startedAt":"2026-10-06T04:00:00Z","endedAt":"2026-10-06T04:00:01Z","exitCode":2,"durationMs":1000,"lastLines":["pg_dump: error: connection refused"]}]}`))
		case "/v1/incidents":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"counts":{"open":2,"fixedThisWeek":1,"all":3},"incidents":[{"id":"i12","ref":"INC-12","title":"checkout-api-prod answering with server errors","severity":"critical","status":"acknowledged","startedAt":"2026-10-10T10:42:00Z","fixedAt":null,"limited":false,"sourceName":"Server","certainty":"confirmed","where":"checkout-api-prod"},{"id":"i11","ref":"INC-11","title":"storefront-web: errors in users' browsers","severity":"critical","status":"open","startedAt":"2026-10-10T09:09:00Z","fixedAt":null,"limited":false,"sourceName":"Frontend","certainty":"confirmed","where":null}]}`))
		case "/v1/incidents/INC-11":
			_, _ = w.Write([]byte(`{"id":"i11","ref":"INC-11","title":"storefront-web: errors in users' browsers","severity":"critical","status":"open","startedAt":"2026-10-10T09:09:00Z","limited":false,"sourceName":"Frontend","certainty":"confirmed","explain":"This morning at 09:09, some pages did not work in customers' browsers. The fault is in an update to the website itself.","sentence":"The errors happen in the browser, after a new frontend version went out.","evidence":[{"area":"browser","text":"214 errors on /checkout/payment since 09:09, all on version 2.14.0.","verdict":"points"},{"area":"database","text":"No slow queries and no refused connections.","verdict":"healthy"}],"timeline":[{"at":"2026-10-10T09:05:00Z","kind":"deploy","text":"storefront-web 2.14.0 went out at 09:05."}],"fix":{"title":"Frontend error that starts right after a deploy","happened":"A new frontend version introduced an error in the browser.","why":"The new code reads a value that is missing.","fix":"Roll back.","command":"IMAGE_TAG=2.13.4 docker compose up -d storefront-web"},"teamNote":{"ref":"INC-4","note":"Rolled back, added the missing check.","by":"Tunde B."}}`))
		case "/v1/incidents/INC-11/ack":
			serverCalls = append(serverCalls, "ack INC-11")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/incidents/INC-11/fix":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			serverCalls = append(serverCalls, "fix INC-11 "+in["note"])
			w.WriteHeader(http.StatusNoContent)
		case "/v1/traces":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"traces":[{"id":"req_2b77f0d3","method":"GET","path":"/api/orders/export","status":200,"startedAt":"2026-10-10T10:39:39Z","totalMs":8470,"lead":"85% of this request was spent inside the backend, outside its database queries.","short":"Backend, 85% of the time"},{"id":"req_9d04c1be","method":"POST","path":"/api/orders","status":502,"startedAt":"2026-10-10T10:41:06Z","totalMs":31,"lead":"","short":"Stopped at the web server: the backend was not running"}]}`))
		case "/v1/traces/req_2b77f0d3":
			_, _ = w.Write([]byte(`{"id":"req_2b77f0d3","method":"GET","path":"/api/orders/export","status":200,"startedAt":"2026-10-10T10:39:39Z","totalMs":8470,"lead":"85% of this request was spent inside the backend, outside its database queries.","short":"Backend, 85% of the time","steps":[{"key":"browser","label":"Browser","detail":"Waiting for the answer","ms":8470,"offset":0,"how":"measured"},{"key":"db","label":"Database","detail":"orders, one query","ms":1200,"offset":300,"how":"matched"},{"key":"inside","label":"Inside the app","detail":"Outside the database","ms":7212,"offset":1258,"how":"worked_out"}],"lines":[{"at":"2026-10-10T10:39:47Z","level":"info","source":"caddy","where":"server","name":"checkout-api-prod","text":"{\"logger\":\"http.log.access.log0\",\"msg\":\"handled request\",\"request\":{\"method\":\"GET\",\"uri\":\"/api/orders/export\"},\"duration\":8.42,\"status\":200}"}]}`))
		case "/v1/logs/export":
			setLastLogsQuery(r.URL.Query())
			if r.URL.Query().Get("server") == "s2" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"not_allowed","message":"Your role does not allow downloading logs. Ask an owner or admin to download them."}`))
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("2026-10-10T10:40:31Z  ERROR  checkout-api-prod  checkout-api  FATAL ERROR: Reached heap limit\n"))
		case "/v1/logs":
			q := r.URL.Query()
			setLastLogsQuery(q)
			if q.Get("since") != "" {
				// Follow: the line already printed again, and one new line.
				n := followPolls.Add(1)
				_, _ = w.Write([]byte(`{"lines":[{"id":"a2","at":"2026-10-10T10:40:31Z","serverName":"checkout-api-prod","source":"checkout-api","level":"error","text":"FATAL ERROR: Reached heap limit"},{"id":"n` + fmt.Sprint(n) + `","at":"2026-10-10T10:41:0` + fmt.Sprint(n) + `Z","serverName":"checkout-api-prod","source":"caddy","level":"info","text":"new line ` + fmt.Sprint(n) + `"}],"more":false,"notice":null}`))
				// Ctrl+C during the third ask: the first two have been printed.
				if n == 3 {
					_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
				}
				return
			}
			_, _ = w.Write([]byte(`{"lines":[{"id":"a1","at":"2026-10-10T10:39:10Z","serverName":"checkout-api-prod","source":"checkout-api","level":"warn","text":"Heap usage at 91% of the limit"},{"id":"a2","at":"2026-10-10T10:40:31Z","serverName":"checkout-api-prod","source":"checkout-api","level":"error","text":"FATAL ERROR: Reached heap limit"}],"more":true,"notice":"over_allowance"}`))
		case "/v1/servers/s1/metrics":
			_, _ = w.Write([]byte(`{"step":300,"cpu":[[1,10],[2,40],[3,31.5]],"memory":[[1,50],[2,52]],"disk":{"/":[[1,30]]},"requests":[[1,60],[2,90]],"errors":[[1,0],[2,3]],"p95":[[1,80],[2,120]],"deploys":[{"id":"1","at":"` + seen + `","kind":"deploy","title":"Deployed checkout-api 3.8.1 (by ada)"}],"containers":{"cpu":{},"memory":{}}}`))
		case "/v1/work":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"counts":{"everyone":3,"mine":1,"unassigned":2},"unassigned":[{"key":"incident:6a1","kind":"incident","title":"INC-11: storefront-web: errors in users' browsers","where":"","severity":"critical","since":null,"state":"open","owner":null,"note":null,"lastFix":null},{"key":"job:6ac9e0a1b2c3d4e5f6a7b8c9","kind":"job","title":"nightly-backup did not run when it was expected","where":"checkout-db-prod","severity":"critical","since":null,"state":"open","owner":null,"note":null,"lastFix":{"note":"Freed space on /var/backups","by":"Amaka Obi"}}],"people":[{"id":"u1","name":"Ada Obi","you":true,"open":1,"items":[{"key":"database:6acc00000000000000d00d01","kind":"database","title":"orders: at the rate it grew, storage is full in about 9 days","where":"checkout-db-prod","severity":"warning","since":null,"state":"acknowledged","owner":{"id":"u1","name":"Ada Obi"},"note":null,"lastFix":null}]}],"incomplete":false}`))
		case "/v1/work/suggest":
			_, _ = w.Write([]byte(`{"item":{"key":"job:x","title":"t","where":"w"},"suggestion":{"userId":"u2","reason":"It is a job on a server, and Ifeoma Nwosu is on call."},"candidates":[{"id":"u1","name":"Ada Obi","open":1,"you":true},{"id":"u2","name":"Ifeoma Nwosu","open":2,"you":false},{"id":"u3","name":"Amaka Obi","open":0,"you":false}],"notListed":["Kemi Lawal"]}`))
		case "/v1/work/assign", "/v1/work/ack", "/v1/work/fix":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			serverCalls = append(serverCalls, fmt.Sprintf("%s %v %v %v", r.URL.Path, in["key"], in["to"], in["note"]))
			w.WriteHeader(http.StatusNoContent)
		case "/v1/team":
			_, _ = w.Write([]byte(`{"people":[{"id":"u1","name":"Ada Obi","email":"ada@example.com","you":true,"role":{"id":"owner","name":"Owner"},"canSee":"Everything","endsAt":null,"area":"devops","alertsGoTo":"Telegram: Ada","twoStep":true},{"id":"u3","name":"Amaka Obi","email":"amaka@example.com","you":false,"role":{"id":"member","name":"Member"},"canSee":"Checkout","endsAt":null,"area":"backend","alertsGoTo":"Email","twoStep":true,"scope":{"all":false,"projects":[{"projectId":"p2","environments":["production"]}]}}],"invites":[{"id":"i1","email":"seun@example.com","role":{"name":"Viewer"},"expired":false,"expiresAt":"2026-10-18T00:00:00Z"}]}`))
		case "/v1/team/invites":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			serverCalls = append(serverCalls, fmt.Sprintf("invite %v %v %v", in["email"], in["role"], in["area"]))
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"i2","emailed":false,"link":"https://app.kiyesi.dev/join/?invite=abc"}`))
		case "/v1/projects/p1", "/v1/projects/p2":
			id := strings.TrimPrefix(r.URL.Path, "/v1/projects/")
			// In Globex the person is a viewer: settings changes are hidden.
			if r.Header.Get("X-Kiyesi-Team") == "bbbbbbbbbbbbbbbbbbbbbbbb" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not_found","message":"Not found."}`))
				return
			}
			if r.Method == http.MethodPatch {
				var in map[string]string
				_ = json.NewDecoder(r.Body).Decode(&in)
				serverCalls = append(serverCalls, "rename "+id+" "+in["name"])
				_, _ = w.Write([]byte(`{"id":"` + id + `","name":"` + in["name"] + `"}`))
				return
			}
			serverCalls = append(serverCalls, "delete project "+id)
			w.WriteHeader(http.StatusNoContent)
		case "/v1/projects/p1/uses":
			_, _ = w.Write([]byte(`{"uses":[{"one":"server","many":"servers","count":2,"where":"/servers/"},{"one":"uptime check","many":"uptime checks","count":1,"where":"/uptime/"}]}`))
		case "/v1/projects/p2/uses":
			_, _ = w.Write([]byte(`{"uses":[]}`))
		case "/v1/uptime/u1":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			body, _ := json.Marshal(in)
			serverCalls = append(serverCalls, "edit u1 "+string(body))
			_, _ = w.Write([]byte(`{}`))
		case "/v1/deploys/d1":
			serverCalls = append(serverCalls, "remove deploy d1")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/team/leave":
			serverCalls = append(serverCalls, "leave")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/me/sessions":
			_, _ = w.Write([]byte(`{"sessions":[{"id":"se1","device":"Chrome on macOS","address":"203.0.113.9","signedInAt":"2026-10-01T09:00:00Z","lastUsedAt":"2026-10-12T09:00:00Z","current":true},{"id":"se2","device":"The kiyesi command","address":null,"signedInAt":"2026-10-02T09:00:00Z","lastUsedAt":"2026-10-11T09:00:00Z","current":false}]}`))
		case "/v1/me/sessions/se2":
			serverCalls = append(serverCalls, "end se2")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/me/sessions/end-others":
			serverCalls = append(serverCalls, "end others")
			if r.Header.Get("X-Kiyesi-Team") == "bbbbbbbbbbbbbbbbbbbbbbbb" {
				_, _ = w.Write([]byte(`{"ended":0}`))
				return
			}
			_, _ = w.Write([]byte(`{"ended":1}`))
		case "/v1/credit":
			if creditBody != "" {
				_, _ = w.Write([]byte(creditBody))
				return
			}
			_, _ = w.Write([]byte(`{"live":true,"selling":true,"canBuy":true,"balance":120,"daysLeft":20,"usedLastWeek":42,"runsOutOn":"2026-11-02T00:00:00Z","state":{"storing":true,"readOnly":false,"eraseOn":null},"bundles":[{"credits":100,"usd":15,"perServerMonth":4.5}],"lines":[{"at":"2026-10-13T00:20:00Z","amount":-6,"reason":"6 servers on 12 October 2026"}]}`))
		case "/v1/projects":
			_, _ = w.Write([]byte(`{"projects":[{"id":"p1","name":"Storefront"},{"id":"p2","name":"Demo client"}]}`))
		case "/v1/me/access":
			_, _ = w.Write([]byte(`{"role":{"id":"6acc00000000000000000001","name":"Frontend contractor"},"levels":{"servers":"act","logs":"hidden","incidents":"act","browser_errors":"act","metrics":"view"},"switches":{"export":false},"canSee":"Storefront, production only, except web-2","endsAt":"2026-11-30T23:59:59Z","team":"Acme"}`))
		case "/v1/roles":
			_, _ = w.Write([]byte(`{"roles":[{"id":"owner","name":"Owner","builtIn":true,"levels":{"servers":"manage"},"copiedFrom":null,"people":[{"name":"Ada"}]},{"id":"viewer","name":"Viewer","builtIn":true,"levels":{"servers":"view"},"copiedFrom":null,"people":[]},{"id":"client","name":"Client","builtIn":true,"levels":{"uptime":"view","servers":"hidden"},"copiedFrom":null,"people":[]},{"id":"6acc00000000000000000001","name":"Frontend contractor","builtIn":false,"levels":{"servers":"act","logs":"hidden"},"copiedFrom":"Member","people":[{"name":"Kemi"}]}]}`))
		case "/v1/team/members/u3/access":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			b, _ := json.Marshal(in)
			serverCalls = append(serverCalls, "access "+string(b))
			if in["twoStepCode"] != "123456" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"two_step_failed","message":"That code is not right. Type the current 6-digit code from your authenticator app."}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/v1/activity":
			setLastLogsQuery(r.URL.Query())
			_, _ = w.Write([]byte(`{"lines":[{"id":"1","at":"2026-10-11T09:20:00Z","by":{"id":"u1","name":"Ada Obi"},"byLabel":null,"sentence":"Assigned INC-11 to Tunde Bello."},{"id":"2","at":"2026-10-11T09:05:00Z","by":null,"byLabel":"Kiyesi","sentence":"Escalated INC-12 to Ifeoma Nwosu: nobody acknowledged it in 15 minutes."}],"next":null}`))
		case "/api/auth/sign-out":
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func signInForTest(t *testing.T) *httptest.Server {
	t.Helper()
	t.Setenv("KIYESI_CONFIG", t.TempDir())
	keychain = noKeychain{}
	opened := ""
	openBrowser = func(u string) { opened = u }
	sleep = func(context.Context, time.Duration) error { return nil }
	srv := fakeAPI(t, 2)
	code, out, errOut := runCLI(t, "login", "--api", srv.URL)
	if code != ExitOK {
		t.Fatalf("login: exit %d: %s %s", code, out, errOut)
	}
	for _, want := range []string{"ABCD-EFGH", "Signed in as Ada (ada@example.com), Owner in Acme."} {
		if !strings.Contains(out, want) {
			t.Errorf("login output is missing %q:\n%s", want, out)
		}
	}
	if opened != "https://app.kiyesi.dev/device?user_code=ABCD-EFGH" {
		t.Errorf("opened %q", opened)
	}
	return srv
}

func TestLoginWaitsForApprovalAndKeepsTheTokenPrivate(t *testing.T) {
	signInForTest(t)
	path, _ := loginPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("login file mode = %v, want 0600", info.Mode().Perm())
	}
	if dir, _ := os.Stat(filepath.Dir(path)); dir.Mode().Perm() != 0o700 {
		t.Errorf("config folder mode = %v, want 0700", dir.Mode().Perm())
	}
}

func TestServersListsWorstFirstWithGradeAndPlace(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "servers")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"NAME", "CPU", "32%", "52%", "30%", "checkout-api-prod", "D 55", "Shop · production", "30 s ago", "new-box", "not connected"} {
		if !strings.Contains(out, want) {
			t.Errorf("servers output is missing %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "servers", "--json")
	if code != ExitOK || !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("--json: exit %d: %s", code, out)
	}
}

func TestServerShowsTheStoredReport(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "server", "CHECKOUT-API-PROD")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"Kiyesi 0.1.0 · checkout-api-prod · scanned ", "CRITICAL", "Fix:"} {
		if !strings.Contains(out, want) {
			t.Errorf("server output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "nothing leaves this server") {
		t.Error("a stored report must not say nothing leaves the server")
	}
	if code, out, _ := runCLI(t, "server", "new-box"); code != ExitOK || !strings.Contains(out, "has not sent a scan yet") {
		t.Errorf("new-box: exit %d: %s", code, out)
	}
	if code, _, errOut := runCLI(t, "server", "nope"); code != ExitUsage || !strings.Contains(errOut, "kiyesi servers") {
		t.Errorf("unknown name: exit %d: %s", code, errOut)
	}
}

func TestSignedOutSaysToLogIn(t *testing.T) {
	t.Setenv("KIYESI_CONFIG", t.TempDir())
	keychain = noKeychain{}
	code, _, errOut := runCLI(t, "servers")
	if code != ExitNoAccess || !strings.Contains(errOut, "kiyesi login") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestLogoutForgetsTheToken(t *testing.T) {
	signInForTest(t)
	if code, out, _ := runCLI(t, "logout"); code != ExitOK || !strings.Contains(out, "Signed out") {
		t.Fatalf("logout: exit %d: %s", code, out)
	}
	if code, _, _ := runCLI(t, "servers"); code != ExitNoAccess {
		t.Errorf("after logout: exit %d, want %d", code, ExitNoAccess)
	}
	// Signing out twice: say so, do not claim to sign out again.
	if code, out, _ := runCLI(t, "logout"); code != ExitOK || !strings.Contains(out, "You were not signed in.") || strings.Contains(out, "Signed out") {
		t.Errorf("second logout: exit %d: %s", code, out)
	}
}

func TestLogoutSaysWhenTheServiceSessionStaysLive(t *testing.T) {
	srv := signInForTest(t)
	path, _ := loginPath()
	if err := os.WriteFile(path, []byte("api: "+srv.URL+"\ntoken: broken-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "logout")
	if code != ExitOK || !strings.Contains(out, "Signed out here; the session on the service could not be ended: end it with kiyesi sessions or the dashboard.") {
		t.Errorf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the token must still be forgotten here")
	}
}

func TestLoginAgainKeepsTheTeamAndEndsTheOldSession(t *testing.T) {
	srv := signInForTest(t)
	path, _ := loginPath()
	if err := os.WriteFile(path, []byte("api: "+srv.URL+"\ntoken: old-token\nteam: bbbbbbbbbbbbbbbbbbbbbbbb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signOuts = nil
	code, out, errOut := runCLI(t, "login", "--api", srv.URL)
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if !strings.Contains(out, "Signed in as Ada (ada@example.com), Viewer in Globex.") {
		t.Errorf("want the kept team and its role name: %s", out)
	}
	if l, err := loadLogin(); err != nil || l.Team != "bbbbbbbbbbbbbbbbbbbbbbbb" || l.Token != personToken {
		t.Errorf("login.yaml = %+v, %v", l, err)
	}
	if len(signOuts) != 1 || signOuts[0] != "old-token" {
		t.Errorf("the old session must be ended: %v", signOuts)
	}
	// A team the person is not in is not kept.
	if err := os.WriteFile(path, []byte("api: "+srv.URL+"\ntoken: old-token\nteam: cccccccccccccccccccccccc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCLI(t, "login", "--api", srv.URL); code != ExitOK || !strings.Contains(out, "Owner in Acme.") {
		t.Errorf("exit %d: %s", code, out)
	}
	if l, _ := loadLogin(); l.Team != "" {
		t.Errorf("team = %q, want none", l.Team)
	}
}

// A connection dropped on the way, a service restarting or "too many
// requests" is asked again: one such ask used to end the sign-in. Asks that
// keep failing stop after about two minutes, with the reason.
func TestLoginWaitsThroughAFailedAsk(t *testing.T) {
	sleep = func(context.Context, time.Duration) error { return nil }
	asks := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asks++
		switch asks {
		case 1: // the connection dropped, as on the owner's Windows laptop
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		case 3:
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"statusCode":429,"error":"too_many_requests","message":"Too many requests."}`))
		case 4:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
		default:
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		}
	}))
	defer srv.Close()
	token, err := poll(context.Background(), api.New(srv.URL, ""), api.DeviceCode{DeviceCode: "d", Interval: 5, ExpiresIn: 600})
	if err != nil || token != "tok" || asks != 5 {
		t.Fatalf("token %q, err %v, after %d asks", token, err, asks)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer down.Close()
	_, err = poll(context.Background(), api.New(down.URL, ""), api.DeviceCode{DeviceCode: "d", Interval: 5, ExpiresIn: 600})
	var e *exitError
	if !errors.As(err, &e) || !strings.Contains(e.msg, "Check your connection") {
		t.Errorf("unreachable: %v", err)
	}
}
