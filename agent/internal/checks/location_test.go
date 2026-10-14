package checks

import (
	"context"
	"errors"
	"fmt"
	"github.com/kiyesi/kiyesi/agent/internal/system"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeMetadata answers like a provider's metadata address.
type fakeMetadata struct {
	answers map[string]string
	asked   []string
}

func (f *fakeMetadata) Get(_ context.Context, method, path string, headers map[string]string) (string, error) {
	f.asked = append(f.asked, method+" "+path)
	if v, ok := f.answers[method+" "+path]; ok {
		return v, nil
	}
	return "", errors.New("no answer")
}

func TestServerLocationFromCloudInit(t *testing.T) {
	e := newTestEnv().saved(t, "run/cloud-init/instance-data.json", "instance-data-do-lon1.json")
	r := run(t, serverLocationCheck{}, e)
	wantStatus(t, r, StatusFail, "outside")
	if v := r.Findings[0].Vars; v["place"] != "London, UK" || v["home"] != "Nigeria" || !strings.Contains(v["rule"], "Central Bank of Nigeria") {
		t.Errorf("vars = %v", v)
	}
	if l := r.Locations[0]; l.Name != "DigitalOcean, London, UK" || l.Confidence != "confirmed" || l.Country != "GB" {
		t.Errorf("row = %+v", l)
	}
	// With the UK as the home country, the same server passes.
	uk := newTestEnv().saved(t, "run/cloud-init/instance-data.json", "instance-data-do-lon1.json")
	uk.cfg.HomeCountry = "GB"
	wantStatus(t, run(t, serverLocationCheck{}, uk), StatusPass)
}

func TestServerLocationFromMetadataAddress(t *testing.T) {
	aws := &fakeMetadata{answers: map[string]string{
		http.MethodPut + " /latest/api/token":                  "token",
		http.MethodGet + " /latest/meta-data/placement/region": "af-south-1",
	}}
	e := newTestEnv().file("sys/class/dmi/id/sys_vendor", "Amazon EC2\n")
	env := e.env()
	env.Sys.Metadata = aws
	r := serverLocationCheck{}.Run(context.Background(), env)
	wantStatus(t, r, StatusFail, "outside")
	if r.Findings[0].Vars["place"] != "Cape Town, South Africa" {
		t.Errorf("place = %q", r.Findings[0].Vars["place"])
	}
	// Only the provider the firmware names is asked, and nothing else.
	for _, a := range aws.asked {
		if !strings.Contains(a, "/latest/") {
			t.Errorf("asked %q", a)
		}
	}
	hetzner := &fakeMetadata{answers: map[string]string{http.MethodGet + " /hetzner/v1/metadata/availability-zone": "fsn1-dc14"}}
	e2 := newTestEnv().file("sys/class/dmi/id/sys_vendor", "Hetzner\n")
	env2 := e2.env()
	env2.Sys.Metadata = hetzner
	if r := (serverLocationCheck{}).Run(context.Background(), env2); r.Locations[0].Name != "Hetzner, Falkenstein, Germany" {
		t.Errorf("hetzner row = %+v", r.Locations)
	}
}

func TestServerLocationUnknownIsSkipped(t *testing.T) {
	r := run(t, serverLocationCheck{}, newTestEnv().file("sys/class/dmi/id/sys_vendor", "Dell Inc.\n"))
	if r.Status != StatusSkip || r.SkipKey != "unknown" || r.Locations[0].Country != "" {
		t.Errorf("result = %+v", r)
	}
}

func appEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv().saved(t, "run/cloud-init/instance-data.json", "instance-data-do-lon1.json")
	e.fs["srv/checkout/.env"] = &fstest.MapFile{Data: []byte(strings.Join([]string{
		"DATABASE_URL=postgres://app:s3cret-pass@db-postgresql-lon1-12345-do-user-678-0.b.db.ondigitalocean.com:25060/checkout?sslmode=require",
		"REDIS_URL=redis://:hunter2hunter2@redis:6379/0",
		"MONGO_URI=mongodb+srv://u:" + "p@cluster0.abcd.mongodb.net/app",
		"SENTRY_DSN=https://abc123@o12345.ingest.de.sentry.io/678",
		"SMTP_HOST=smtp.resend.com",
		"TERMII_API_KEY=TLxxxx",
		"RESTIC_REPOSITORY=s3:https://s3.eu-central-003.backblazeb2.com/checkout-backups",
	}, "\n") + "\n"), Mode: 0o600}
	e.fs["root/.config/rclone/rclone.conf"] = &fstest.MapFile{Data: []byte("[offsite]\ntype = s3\nprovider = AWS\nregion = af-south-1\naccess_key_id = AKIA0000\n"), Mode: 0o600}
	e.fs["etc/cron.d/backup"] = &fstest.MapFile{Data: []byte("0 4 * * * root aws s3 sync /var/backups s3://checkout-db-dumps --region eu-west-2\n")}
	e.cfg.Secrets.Paths = []string{"/srv", "/root"}
	return e
}

func TestDatabaseConnections(t *testing.T) {
	r := run(t, databaseConnectionsCheck{}, appEnv(t))
	wantStatus(t, r, StatusFail, "outside")
	if v := r.Findings[0].Vars; v["host"] != "db-postgresql-lon1-12345-do-user-678-0.b.db.ondigitalocean.com:25060" || v["place"] != "London, UK" {
		t.Errorf("vars = %v", v)
	}
	var names []string
	for _, l := range r.Locations {
		names = append(names, l.Name+"|"+l.Confidence+"|"+l.Country)
		for _, bad := range []string{"s3cret", "hunter2", "app:", ":p@"} {
			if strings.Contains(l.Name, bad) {
				t.Fatalf("a credential reached a row: %q", l.Name)
			}
		}
	}
	want := []string{
		"redis (this server)|confirmed|GB",
		"db-postgresql-lon1-12345-do-user-678-0.b.db.ondigitalocean.com:25060|likely|GB",
		"cluster0.abcd.mongodb.net||",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("rows = %v\nwant   %v", names, want)
	}
}

func TestDatabasesInContainersEnvironments(t *testing.T) {
	env := newTestEnv()
	env.docker = fakeDocker{cs: []system.Container{{Name: "kiyesi-valkey-1", ComposeService: "valkey", Image: "valkey/valkey:9.1.2"}, {
		Name: "api",
		Env: []string{
			"PATH=/usr/local/bin",
			"MONGO_URL=mongodb+srv://kiyesi:" + "s3cret@cluster0.abcd.mongodb.net/kiyesi",
			"VALKEY_URL=redis://valkey:6379",
			"CACHE_REDIS_URL=redis://cache:6379",
		},
	}}}
	r := run(t, databaseConnectionsCheck{}, env)
	var rows []string
	for _, l := range r.Locations {
		rows = append(rows, l.Name+"|"+l.Host)
		if strings.Contains(l.Name+l.Host, "s3cret") {
			t.Fatalf("a credential reached a row: %+v", l)
		}
	}
	// valkey is a Compose service on this server, running Valkey; cache is
	// named as Redis, as nothing says otherwise.
	want := "valkey (this server)|,redis (this server)|,cluster0.abcd.mongodb.net|cluster0.abcd.mongodb.net"
	if strings.Join(rows, ",") != want {
		t.Errorf("rows = %v, want %s", rows, want)
	}
}

func TestBackupDestinations(t *testing.T) {
	r := run(t, backupDestinationsCheck{}, appEnv(t))
	wantStatus(t, r, StatusFail, "outside", "outside", "outside")
	got := map[string]string{}
	for _, l := range r.Locations {
		got[l.Name] = l.Place
	}
	for name, place := range map[string]string{
		"rclone remote offsite": "Cape Town, South Africa",
		"restic repository s3:https://s3.eu-central-003.backblazeb2.com/checkout-backups": "Amsterdam, Netherlands",
		"s3://checkout-db-dumps": "London, UK",
	} {
		if got[name] != place {
			t.Errorf("%s = %q, want %q (rows %v)", name, got[name], place, got)
		}
	}
	if got := maskRepo("s3:https://key:secret@s3.example.com/bucket"); got != "s3:https://s3.example.com/bucket" {
		t.Errorf("maskRepo = %q", got)
	}
	if r := run(t, backupDestinationsCheck{}, newTestEnv()); !r.None {
		t.Errorf("no backups configured: %+v", r)
	}
}

func TestOutsideServicesAreListedNeverFlagged(t *testing.T) {
	r := run(t, outsideServicesCheck{}, appEnv(t))
	wantStatus(t, r, StatusPass)
	var names []string
	for _, l := range r.Locations {
		if !l.Review {
			t.Errorf("%s is not marked for review", l.Name)
		}
		names = append(names, l.Name)
	}
	if strings.Join(names, ",") != "Sentry (o12345.ingest.de.sentry.io),Email (SMTP) (smtp.resend.com),Termii" {
		t.Errorf("services = %v", names)
	}
}

func TestPaymentData(t *testing.T) {
	none := appEnv(t)
	if r := run(t, paymentDataCheck{}, none); !r.None {
		t.Errorf("nothing tagged: %+v", r)
	}
	e := appEnv(t)
	e.cfg.PaymentData = []string{"redis", "db-postgresql-lon1-12345-do-user-678-0.b.db.ondigitalocean.com"}
	r := run(t, paymentDataCheck{}, e)
	wantStatus(t, r, StatusFail, "outside", "outside")
	if r.Findings[0].Confidence != "confirmed" || r.Findings[1].Confidence != "likely" {
		t.Errorf("confidence = %q, %q: a database on this server is where the server is", r.Findings[0].Confidence, r.Findings[1].Confidence)
	}
	inside := appEnv(t)
	inside.cfg.HomeCountry = "GB"
	inside.cfg.PaymentData = []string{"redis"}
	wantStatus(t, run(t, paymentDataCheck{}, inside), StatusPass)
}

func TestDatabasesByValueAndOnThePrivateNetwork(t *testing.T) {
	env := newTestEnv()
	env.docker = fakeDocker{cs: []system.Container{{
		Name: "api",
		Env: []string{
			// Named nothing a database is usually named: found by its value.
			"MY_DB_ADDR=postgres://app:s3cret@10.114.0.5:5432/shop",
			"ORDERS_STORE=mongodb://db.vpc.internal:27017/orders",
			// Not a database, though it is an address.
			"WEBHOOK=https://hooks.example.com/x",
			"GREETING=hello",
		},
	}}}
	r := run(t, databaseConnectionsCheck{}, env)
	var rows []string
	for _, l := range r.Locations {
		rows = append(rows, fmt.Sprintf("%s|%s|%v", l.Name, l.Host, l.Private))
		if strings.Contains(l.Name+l.Host, "s3cret") {
			t.Fatalf("a credential reached a row: %+v", l)
		}
	}
	want := "10.114.0.5:5432|10.114.0.5|true,db.vpc.internal:27017|db.vpc.internal|true"
	if strings.Join(rows, ",") != want {
		t.Errorf("rows = %v, want %s", rows, want)
	}
	// On the private network: no finding of its own, the server's covers it.
	for _, f := range r.Findings {
		t.Errorf("unexpected finding %+v", f)
	}
}
