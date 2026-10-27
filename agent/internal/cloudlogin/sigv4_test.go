package cloudlogin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The expected values below were made by botocore 1.43.119, AWS's own
// library, with these keys and this time (scripts in the pull request).
var (
	testKeys = AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "SESSIONTOKENEXAMPLE"}
	testTime = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
)

func frozen(t *testing.T) {
	t.Helper()
	old := clock
	clock = func() time.Time { return testTime }
	t.Cleanup(func() { clock = old })
}

func TestRDSTokenMatchesAWSsOwn(t *testing.T) {
	frozen(t)
	const want = "orders.c9x.eu-west-1.rds.amazonaws.com:5432/?Action=connect&DBUser=kiyesi_ro&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20261027%2Feu-west-1%2Frds-db%2Faws4_request&X-Amz-Date=20261027T120000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Security-Token=SESSIONTOKENEXAMPLE&X-Amz-Signature=026fde50b103ec5deeb935c0c2bc851aae0d677fa497c3c97f2fa51e9fa9778c"
	got := RDSToken(testKeys, "orders.c9x.eu-west-1.rds.amazonaws.com", "5432", "kiyesi_ro", "eu-west-1")
	// The same address, the same signature: the order of the query does not matter to AWS.
	g, _ := url.Parse("https://" + got)
	w, _ := url.Parse("https://" + want)
	if g.Host != w.Host || g.Path != w.Path {
		t.Fatalf("address: got %s", got)
	}
	gq, wq := g.Query(), w.Query()
	for k := range wq {
		if gq.Get(k) != wq.Get(k) {
			t.Errorf("%s: got %q, want %q", k, gq.Get(k), wq.Get(k))
		}
	}
	if len(gq) != len(wq) {
		t.Errorf("got %d query fields, want %d", len(gq), len(wq))
	}
}

func TestSignedRequestsMatchAWSsOwn(t *testing.T) {
	body := []byte(`{"SecretId":"prod/orders/kiyesi_ro"}`)
	r, _ := http.NewRequest(http.MethodPost, "https://secretsmanager.eu-west-1.amazonaws.com/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	r.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	signRequest(r, body, testKeys, "eu-west-1", "secretsmanager", testTime)
	if got, want := r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261027/eu-west-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=53eb1e8d94f33f9b6a7572c55e1e4dc041dd5e0a860f939507aed3cf46a5f080"; got != want {
		t.Errorf("Secrets Manager:\n got %s\nwant %s", got, want)
	}

	frozen(t)
	login, err := VaultAWSLogin(testKeys, "kiyesi", "vault.example.com")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(login["iam_request_headers"])
	var h map[string][]string
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if got, want := h["Authorization"][0], "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261027/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-vault-aws-iam-server-id, Signature=54c9d50b38b6e331f0909512f61e685d6f6d4f8823bc8319d8224a2f16d445d6"; got != want {
		t.Errorf("STS for Vault:\n got %s\nwant %s", got, want)
	}
	if b, _ := base64.StdEncoding.DecodeString(login["iam_request_body"]); string(b) != "Action=GetCallerIdentity&Version=2011-06-15" || login["role"] != "kiyesi" {
		t.Errorf("login: %v", login)
	}
}

func TestRDSRegion(t *testing.T) {
	for host, want := range map[string]string{
		"orders.c9x.eu-west-1.rds.amazonaws.com":                  "eu-west-1",
		"shop.cluster-ro-abc.us-gov-west-1.rds.amazonaws.com":     "us-gov-west-1",
		"pg.c1.cn-north-1.rds.amazonaws.com.cn":                   "cn-north-1",
		"cluster0.ab1cd.mongodb.net":                              "",
		"orders.c9x.eu-west-1.rds.amazonaws.com.attacker.example": "",
	} {
		if got := RDSRegion(host); got != want {
			t.Errorf("%s: got %q, want %q", host, got, want)
		}
	}
	if !strings.Contains(RDSToken(testKeys, "h.c.eu-west-1.rds.amazonaws.com", "3306", "kiyesi_ro", "eu-west-1"), "DBUser=kiyesi_ro") {
		t.Error("the token names the user")
	}
}
