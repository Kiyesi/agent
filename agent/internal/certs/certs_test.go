package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

const body = `{"v":1,"id":"Qm9yX3pXnFv2kTr8aLdE1c0b","issuer":"Kiyesi","team":"Acme","server":"web-1","os":"Ubuntu 24.04","grade":{"letter":"A","score":95},"checks":{"passed":22,"basedOn":24,"total":24},"critical":0,"warnings":1,"breakIn":"no signs","scannedAt":"2026-10-24T08:45:00.000Z","issuedAt":"2026-10-24T09:00:00.000Z","expiresAt":"2026-11-23T09:00:00.000Z"}`

func signed(t *testing.T) (File, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(body))
	return File{Certificate: body, Signature: base64.StdEncoding.EncodeToString(sig)}, base64.StdEncoding.EncodeToString(pub)
}

func TestCheckAcceptsOnlyWhatKiyesiSigned(t *testing.T) {
	f, key := signed(t)
	b, err := Check(f, key)
	if err != nil || b.Server != "web-1" || b.Grade.Letter != "A" || b.BreakIn != "no signs" || b.ExpiresAt.Format("2006-01-02") != "2026-11-23" {
		t.Fatalf("%v %+v", err, b)
	}
	tampered := f
	tampered.Certificate = strings.Replace(body, `"score":95`, `"score":99`, 1)
	if _, err := Check(tampered, key); err != ErrBadSignature {
		t.Fatalf("a changed grade passed: %v", err)
	}
	_, other := signed(t)
	if _, err := Check(f, other); err != ErrBadSignature {
		t.Fatalf("another key passed: %v", err)
	}
	if _, err := Check(f, ""); err == nil {
		t.Fatal("no key passed")
	}
}

func TestIDFromLinkOrID(t *testing.T) {
	for in, want := range map[string]string{
		"https://kiyesi.dev/verify/?id=Qm9yX3pXnFv2kTr8aLdE1c0b":   "Qm9yX3pXnFv2kTr8aLdE1c0b",
		"https://kiyesi.dev/verify/?id=Qm9yX3pXnFv2kTr8aLdE1c0b#x": "Qm9yX3pXnFv2kTr8aLdE1c0b",
		"Qm9yX3pXnFv2kTr8aLdE1c0b":                                 "Qm9yX3pXnFv2kTr8aLdE1c0b",
	} {
		if got, ok := IDFrom(in); !ok || got != want {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "short", "../../../etc/passwd.....", strings.Repeat("Q", 24) + "/x"} {
		if _, ok := IDFrom(bad); ok {
			t.Errorf("%q read as an id", bad)
		}
	}
}

// The key built into a release is Kiyesi's real public key: 32 bytes.
func TestBuiltInKeyIsAnEd25519Key(t *testing.T) {
	k := BuiltInKey()
	if k == "" {
		t.Skip("no key built in")
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("signing.pub = %q: %v, %d bytes", k, err, len(raw))
	}
}
