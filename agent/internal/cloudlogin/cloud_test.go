package cloudlogin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A fake AWS instance metadata service: IMDSv2 only, as AWS recommends.
func fakeIMDS(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			_, _ = io.WriteString(w, "imds-session")
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "imds-session" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = io.WriteString(w, "kiyesi-agent\n")
		case "/latest/meta-data/iam/security-credentials/kiyesi-agent":
			_, _ = io.WriteString(w, `{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"role-secret","Token":"role-token","Expiration":"2026-10-27T18:00:00Z"}`)
		case "/latest/meta-data/placement/region":
			_, _ = io.WriteString(w, "eu-west-1")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	old := awsMetadataURL
	awsMetadataURL = srv.URL
	t.Cleanup(func() { awsMetadataURL = old })
}

func TestAWSKeysFromTheInstanceRole(t *testing.T) {
	fakeIMDS(t)
	c, err := AWSCredentialsFor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "ASIAEXAMPLE" || c.SecretAccessKey != "role-secret" || c.SessionToken != "role-token" || c.Expires.IsZero() {
		t.Errorf("keys: %+v", c)
	}
	if r := AWSRegion(context.Background()); r != "eu-west-1" {
		t.Errorf("region %q", r)
	}
}

func TestNoRoleSaysWhatToDo(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	old := awsMetadataURL
	awsMetadataURL = "http://127.0.0.1:1"
	t.Cleanup(func() { awsMetadataURL = old })
	_, err := AWSCredentialsFor(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Attach an IAM role") {
		t.Errorf("got %v", err)
	}
}

func TestSecretsManagerGivesThePasswordAndNeverEchoesIt(t *testing.T) {
	frozen(t)
	var answer atomic.Value
	answer.Store(`{"SecretString":"{\"username\":\"kiyesi_ro\",\"password\":\"from-aws\"}"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261027/eu-central-1/secretsmanager/aws4_request") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["SecretId"] == "denied" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","Message":"secret text should never be shown"}`)
			return
		}
		_, _ = io.WriteString(w, answer.Load().(string))
	}))
	defer srv.Close()
	old := secretsURL
	secretsURL = func(string) string { return srv.URL + "/" }
	defer func() { secretsURL = old }()

	ctx := context.Background()
	arn := "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/orders-AbCdEf"
	if pw, err := AWSSecret(ctx, testKeys, arn, ""); err != nil || pw != "from-aws" {
		t.Errorf("JSON secret: %q %v", pw, err)
	}
	answer.Store(`{"SecretString":"plain-password"}`)
	if pw, err := AWSSecret(ctx, testKeys, "prod/orders", "eu-central-1"); err != nil || pw != "plain-password" {
		t.Errorf("plain secret: %q %v", pw, err)
	}
	if _, err := AWSSecret(ctx, testKeys, "prod/orders", ""); err == nil || !strings.Contains(err.Error(), "whole ARN") {
		t.Errorf("no region: %v", err)
	}
	_, err := AWSSecret(ctx, testKeys, "denied", "eu-central-1")
	if err == nil || !strings.Contains(err.Error(), "secretsmanager:GetSecretValue") || strings.Contains(err.Error(), "should never") {
		t.Errorf("denied: %v", err)
	}
}

func TestCloudTokensFromTheMetadataServices(t *testing.T) {
	gcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/token") && r.URL.Query().Get("scopes") == gcpSQLScope {
			_, _ = io.WriteString(w, `{"access_token":"gcp-token","expires_in":3599}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/identity") && r.URL.Query().Get("audience") == "vault/kiyesi" {
			_, _ = io.WriteString(w, "gcp.jwt.signed")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer gcp.Close()
	azure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/metadata/identity/oauth2/token" && r.URL.Query().Get("resource") == azureDBTarget {
			_, _ = io.WriteString(w, `{"access_token":"azure-token-`+r.URL.Query().Get("client_id")+`"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer azure.Close()
	og, oa := gcpMetadataURL, azureMetadataURL
	gcpMetadataURL, azureMetadataURL = gcp.URL, azure.URL
	defer func() { gcpMetadataURL, azureMetadataURL = og, oa }()

	ctx := context.Background()
	if tok, err := GCPToken(ctx); err != nil || tok != "gcp-token" {
		t.Errorf("Google Cloud: %q %v", tok, err)
	}
	if jwt, err := GCPIdentityJWT(ctx, "vault/kiyesi"); err != nil || jwt != "gcp.jwt.signed" {
		t.Errorf("Google Cloud identity: %q %v", jwt, err)
	}
	if tok, err := AzureToken(ctx, "", ""); err != nil || tok != "azure-token-" {
		t.Errorf("Azure: %q %v", tok, err)
	}
	if tok, err := AzureToken(ctx, "", "1111-2222"); err != nil || tok != "azure-token-1111-2222" {
		t.Errorf("Azure user-assigned: %q %v", tok, err)
	}
}

// A fake Vault: AppRole sign-in, a key-value secret, and a database
// engine that makes short-lived users whose leases can be renewed.
func TestVaultSignsInReadsAndRenews(t *testing.T) {
	now := testTime
	old := clock
	clock = func() time.Time { return now }
	defer func() { clock = old }()

	var logins, creds, renews atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["role_id"] != "role-1" || b["secret_id"] != "secret-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			logins.Add(1)
			_, _ = io.WriteString(w, `{"auth":{"client_token":"tok","lease_duration":3600}}`)
			return
		}
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/kv/data/db/orders":
			_, _ = io.WriteString(w, `{"data":{"data":{"password":"kv-pw"},"metadata":{"version":3}}}`)
		case "/v1/database/creds/kiyesi-ro":
			n := creds.Add(1)
			_, _ = io.WriteString(w, `{"lease_id":"database/creds/kiyesi-ro/abc`+string(rune('0'+n))+`","lease_duration":900,"data":{"username":"v-kiyesi-`+string(rune('0'+n))+`","password":"dyn-pw"}}`)
		case "/v1/sys/leases/renew":
			if renews.Add(1) > 1 {
				// Its maximum time is reached: Vault gives no more.
				_, _ = io.WriteString(w, `{"lease_duration":30}`)
				return
			}
			_, _ = io.WriteString(w, `{"lease_duration":900}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	v := &Vault{S: VaultSettings{Address: srv.URL, Auth: "approle", Role: "role-1"},
		SecretID: func(context.Context) (string, error) { return "secret-1", nil }}
	ctx := context.Background()

	if l, err := v.Read(ctx, "kv/data/db/orders"); err != nil || l.Password != "kv-pw" || l.Short {
		t.Fatalf("key-value: %+v %v", l, err)
	}
	l, err := v.Read(ctx, "database/creds/kiyesi-ro")
	if err != nil || l.Username != "v-kiyesi-1" || l.Password != "dyn-pw" || !l.Short {
		t.Fatalf("short-lived user: %+v %v", l, err)
	}
	// Within its lease, the same user, and Vault is not asked again.
	now = now.Add(5 * time.Minute)
	if l, _ := v.Read(ctx, "database/creds/kiyesi-ro"); l.Username != "v-kiyesi-1" || creds.Load() != 1 {
		t.Errorf("cached: %+v, %d reads", l, creds.Load())
	}
	// Two thirds through: renewed, still the same user.
	now = now.Add(6 * time.Minute)
	if l, _ := v.Read(ctx, "database/creds/kiyesi-ro"); l.Username != "v-kiyesi-1" || renews.Load() != 1 || creds.Load() != 1 {
		t.Errorf("renewed: %+v, %d renewals, %d reads", l, renews.Load(), creds.Load())
	}
	// Renewal refused more time: a new user.
	now = now.Add(11 * time.Minute)
	if l, _ := v.Read(ctx, "database/creds/kiyesi-ro"); l.Username != "v-kiyesi-2" || creds.Load() != 2 {
		t.Errorf("new user: %+v, %d reads", l, creds.Load())
	}
	if logins.Load() != 1 {
		t.Errorf("signed in %d times, want once", logins.Load())
	}
	if _, err := v.Read(ctx, "kv/data/db/orders#token"); err == nil || !strings.Contains(err.Error(), "no token field") {
		t.Errorf("missing field: %v", err)
	}
	if _, err := v.Read(ctx, "secret/nothing"); err == nil || !strings.Contains(err.Error(), "nothing at secret/nothing") {
		t.Errorf("missing secret: %v", err)
	}
	if _, err := (&Vault{S: VaultSettings{Address: "http://vault.example.com:8200", Auth: "aws"}}).Read(ctx, "kv/x"); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("plain http to another machine: %v", err)
	}
}
