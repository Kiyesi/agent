package collect

import (
	"testing"
	"testing/fstest"
	"time"
)

func TestParseAcceptedReadsTheKey(t *testing.T) {
	at := time.Date(2026, 10, 23, 13, 58, 0, 0, time.UTC)
	for _, c := range []struct{ line, user, addr, method, key string }{
		{"Accepted publickey for root from 203.0.113.9 port 50122 ssh2: ED25519 SHA256:FTTdNdFL7P1Edcs9NJAoKniBAlw3N76qvPVqzpuVeW8", "root", "203.0.113.9", "publickey", "SHA256:FTTdNdFL7P1Edcs9NJAoKniBAlw3N76qvPVqzpuVeW8"},
		{"Accepted publickey for ada from ::ffff:198.51.100.7 port 4 ssh2: RSA SHA256:BEvNIvJXhPSZ6sZYlp+jSrx2h7QWco8li1kZOHLgNTk", "ada", "198.51.100.7", "publickey", "SHA256:BEvNIvJXhPSZ6sZYlp+jSrx2h7QWco8li1kZOHLgNTk"},
		{"Accepted password for deploy from 198.51.100.4 port 40000 ssh2", "deploy", "198.51.100.4", "password", ""},
	} {
		s, ok := parseAccepted(c.line, at)
		if !ok || s.User != c.user || s.Address != c.addr || s.Method != c.method || s.Key != c.key {
			t.Errorf("%q: %+v %v", c.line, s, ok)
		}
	}
	if _, ok := parseAccepted("Failed password for root from 192.0.2.9 port 2 ssh2", at); ok {
		t.Error("a failed sign-in was read as one that worked")
	}
}

func TestSigninsFromTheLogFileWithinTheWindow(t *testing.T) {
	mod := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	fsys := fstest.MapFS{"var/log/auth.log": {ModTime: mod, Data: []byte(
		"2026-10-23T13:58:00.000000+00:00 web-1 sshd[1]: Accepted publickey for root from 203.0.113.9 port 1 ssh2\n" +
			"2026-10-20T10:00:00.000000+00:00 web-1 sshd[2]: Accepted publickey for root from 192.0.2.1 port 1 ssh2\n" +
			"2026-10-23T14:30:00.000000+00:00 web-1 sshd-session[3]: Accepted password for ada from 198.51.100.7 port 9 ssh2\n" +
			"2026-10-23T14:31:00.000000+00:00 web-1 CRON[4]: Accepted publickey for root from 1.2.3.4 port 1 ssh2\n")}}
	got := fileSignins(fsys, time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC))
	if len(got) != 2 || got[0].Address != "203.0.113.9" || got[1].User != "ada" {
		t.Fatalf("got %+v", got)
	}
}
