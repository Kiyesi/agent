package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const certBody = `{"v":1,"id":"Qm9yX3pXnFv2kTr8aLdE1c0b","issuer":"Kiyesi","team":"Acme","server":"web-1","os":"Ubuntu 24.04","grade":{"letter":"A","score":95},"checks":{"passed":22,"basedOn":24,"total":24},"critical":0,"warnings":1,"breakIn":"no signs","scannedAt":"2026-10-24T08:45:00.000Z","issuedAt":"2026-10-24T09:00:00.000Z","expiresAt":"2026-11-23T09:00:00.000Z"}`

func certFile(t *testing.T) (path, sig string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(certBody)))
	oldKey, oldNow, oldAPI := verifyKey, verifyNow, verifyAPI
	t.Cleanup(func() { verifyKey, verifyNow, verifyAPI = oldKey, oldNow, oldAPI })
	verifyKey = func() string { return base64.StdEncoding.EncodeToString(pub) }
	verifyNow = func() time.Time { return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC) }
	data, _ := json.Marshal(map[string]string{"certificate": certBody, "signature": sig})
	path = filepath.Join(t.TempDir(), "kiyesi-certificate-web-1.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, sig
}

func TestVerifyAFileOffline(t *testing.T) {
	path, _ := certFile(t)
	code, out, errOut := runCLI(t, "verify", path)
	if code != ExitOK {
		t.Fatalf("code %d %s %s", code, out, errOut)
	}
	for _, want := range []string{"A real Kiyesi health certificate, unchanged, valid until 23 Nov 2026", "web-1 · 95/100", "of Acme", "22 of 24 checks passed", "Break-in check: no signs", "built into kiyesi", "kiyesi verify Qm9yX3pXnFv2kTr8aLdE1c0b"} {
		if !strings.Contains(out, want) {
			t.Errorf("out lacks %q:\n%s", want, out)
		}
	}
	verifyNow = func() time.Time { return time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC) }
	if code, out, _ := runCLI(t, "verify", path); code != ExitFindings || !strings.Contains(out, "expired on 23 Nov 2026") {
		t.Fatalf("expired: %d\n%s", code, out)
	}
}

func TestVerifyRefusesAChangedCertificate(t *testing.T) {
	path, sig := certFile(t)
	changed, _ := json.Marshal(map[string]string{"certificate": strings.Replace(certBody, `"letter":"A","score":95`, `"letter":"A","score":100`, 1), "signature": sig})
	_ = os.WriteFile(path, changed, 0o600)
	code, _, errOut := runCLI(t, "verify", path)
	if code != ExitFindings || !strings.Contains(errOut, "Not a real certificate") {
		t.Fatalf("code %d %q", code, errOut)
	}
}

func TestVerifyByLinkAsksWhetherItWasRevoked(t *testing.T) {
	_, sig := certFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/public/certificates/Qm9yX3pXnFv2kTr8aLdE1c0b" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": certBody, "signature": sig, "status": "revoked"})
	}))
	defer srv.Close()
	verifyAPI = func() string { return srv.URL }
	code, out, _ := runCLI(t, "verify", "https://kiyesi.dev/verify/?id=Qm9yX3pXnFv2kTr8aLdE1c0b")
	if code != ExitFindings || !strings.Contains(out, "it was revoked") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if code, _, errOut := runCLI(t, "verify", "Zz9yX3pXnFv2kTr8aLdE1c0b"); code != ExitFindings || !strings.Contains(errOut, "No certificate has that id") {
		t.Fatalf("unknown id: %d %q", code, errOut)
	}
	if code, _, _ := runCLI(t, "verify", "nonsense"); code != ExitUsage {
		t.Fatalf("nonsense: %d", code)
	}
}
