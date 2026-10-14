package mask

import (
	"strings"
	"testing"
)

// fake joins pieces, so the made-up secrets below are built at runtime and
// secret scanners do not mistake the test for a leak.
func fake(parts ...string) string { return strings.Join(parts, "") }

// Secrets that must never survive masking, in the places they turn up.
var cases = []struct{ in, secret string }{
	{"postgres://app:s3cretPass@db.example.com:5432/app", "s3cretPass"},
	{"mongodb+srv://admin:" + "Hunter2Hunter2@cluster0.abcd.mongodb.net/app", "Hunter2Hunter2"},
	{"redis://:longredispassword@redis:6379/0", "longredispassword"},
	{"DB_PASSWORD=correct-horse-battery", "correct-horse-battery"},
	{"POSTGRES_PASSWORD: hunter2hunter2", "hunter2hunter2"},
	{`{"apiKey": "` + fake("abcd1234", "efgh5678") + `"}`, fake("abcd1234", "efgh5678")},
	{"export AWS_SECRET_ACCESS_KEY=" + fake("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCYEXAMPLEKEY"), fake("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCYEXAMPLEKEY")},
	{"aws key AKIAIOSFODNN7EXAMPLE in a log line", "AKIAIOSFODNN7EXAMPLE"},
	{"token " + fake("gh", "p_", "0123456789abcdefghijABCDEFGHIJ0123456789"), fake("gh", "p_", "0123456789abcdefghijABCDEFGHIJ0123456789")},
	{"Authorization: Bearer " + fake("ey", "JhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"), "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	{"GET /callback?code=1&token=" + fake("abcdef", "123456") + "&x=2", fake("abcdef", "123456")},
	{"PAYSTACK_SECRET_KEY=" + "sk_" + "live_9f3b2c1d4e5f6a7b8c9d0e1f", "9f3b2c1d4e5f6a7b8c9d0e1f"},
	{fake("-----BEGIN OPENSSH ", "PRIVATE KEY-----\n") + fake("b3BlbnNzaC1y", "ZXktdjEAAAAABG5vbmU=") + "\n-----END OPENSSH PRIVATE KEY-----", fake("b3BlbnNzaC1y", "ZXktdjEAAAAABG5vbmU")},
	{"slack xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij"},
	{"redis-cli -h redis -a supersecretpassword ping", "supersecretpassword"},
	{"mysqldump -u root -pTopSecret99 shop > dump.sql", "TopSecret99"},
	{"pg_dump --password 'Quoted Secret' app", "Quoted Secret"},
}

func TestStringRemovesSecrets(t *testing.T) {
	for _, c := range cases {
		got := String(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("secret survived:\n in: %q\nout: %q", c.in, got)
		}
		if !strings.Contains(got, Masked) {
			t.Errorf("no [masked] marker in %q", got)
		}
	}
}

func TestStringKeepsWhatIsNotSecret(t *testing.T) {
	for _, s := range []string{
		"Redis is open to the internet on port 6379",
		"db-postgresql-lon1-12345-do-user-678-0.b.db.ondigitalocean.com:25060",
		"sudo chmod 600 /srv/app/.env",
		"PasswordAuthentication no",
		"checkout-api-prod · Ubuntu 22.04 · 22 checks in 6.4 s",
	} {
		if got := String(s); got != s {
			t.Errorf("changed text with no secret:\n in: %q\nout: %q", s, got)
		}
	}
	if got := String("postgres://app:s3cret@db.example.com/app"); got != "postgres://app:[masked]@db.example.com/app" {
		t.Errorf("host was not kept: %q", got)
	}
}

type report struct {
	Name     string
	Findings []struct{ Fix string }
	Extra    map[string]string
	Any      map[string]any
	Ptr      *string
}

func TestValueWalksEverything(t *testing.T) {
	s := "token=" + fake("abcdef", "123456")
	r := report{
		Name:     "DB_PASSWORD=hunter2hunter2",
		Findings: []struct{ Fix string }{{Fix: "mysql -u root -p'x' postgres://u:pw1234@h/db"}},
		Extra:    map[string]string{"dsn": "redis://:longpass@r:6379"},
		Any:      map[string]any{"nested": map[string]any{"k": "API_KEY=" + fake("abcd", "1234efgh")}, "list": []any{"secret=abcdefgh"}},
		Ptr:      &s,
	}
	Value(&r)
	all := r.Name + r.Findings[0].Fix + r.Extra["dsn"] + *r.Ptr
	for _, secret := range []string{"hunter2hunter2", "pw1234", "longpass", fake("abcdef", "123456")} {
		if strings.Contains(all, secret) {
			t.Errorf("%q survived in %q", secret, all)
		}
	}
	if strings.Contains(r.Any["nested"].(map[string]any)["k"].(string), "abcd1234efgh") {
		t.Errorf("nested map value survived: %v", r.Any)
	}
	if strings.Contains(r.Any["list"].([]any)[0].(string), "abcdefgh") {
		t.Errorf("value in a list in a map survived: %v", r.Any)
	}
}
