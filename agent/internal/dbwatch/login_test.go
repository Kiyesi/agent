package dbwatch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/cloudlogin"
)

func login(t *testing.T, c Config) (Secret, error) {
	t.Helper()
	u, err := url.Parse(c.URL)
	if err != nil {
		t.Fatal(err)
	}
	return LoginFor(context.Background(), c, u)
}

// Nobody keeps a database password in plain text: one in the address is
// refused, with where to go instead, and the reader says so without it.
func TestAPasswordInTheAddressIsRefused(t *testing.T) {
	_, err := login(t, Config{Name: "orders", URL: "postgres://kiyesi_ro:secret@127.0.0.1/orders"})
	if !errors.Is(err, ErrPasswordInAddress) {
		t.Fatalf("err = %v", err)
	}
	f := (&Reader{}).Read(context.Background(), Config{Name: "orders", URL: "postgres://kiyesi_ro:secret@127.0.0.1/orders"}, time.Now())
	if !strings.Contains(f.Error, "sudo kiyesi databases setup") || strings.Contains(f.Error, "secret") || f.Login != "" {
		t.Errorf("figures = %+v", f)
	}
}

func TestSocketAndNoPassword(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres://kiyesi_ro@/orders?host=/var/run/postgresql":               LoginSocket,
		"mysql://kiyesi_ro@localhost/shop?socket=/var/run/mysqld/mysqld.sock": LoginSocket,
		"redis://127.0.0.1:6379": LoginNone,
	} {
		s, err := login(t, Config{Name: "db", URL: raw})
		if err != nil || s.Kind != want || s.Password != "" {
			t.Errorf("%s: %+v %v", raw, s, err)
		}
	}
	if _, err := login(t, Config{Name: "db", URL: "redis://127.0.0.1", Password: "hunter2"}); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("a password typed in the password setting: %v", err)
	}
}

func TestOwnEncryptedPassword(t *testing.T) {
	ownTestStore(t)
	sealed, err := Encrypt("orders", "s3cret")
	if err != nil || strings.Contains(sealed, "s3cret") || !strings.HasPrefix(sealed, "kiyesi-enc-v1:") {
		t.Fatalf("sealed %q, %v", sealed, err)
	}
	if info, err := os.Stat(KeyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key: %v %v", info, err)
	}
	if err := os.WriteFile(filepath.Join(OwnCredentialsDir, "orders.enc"), []byte(sealed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := login(t, Config{Name: "orders", URL: "postgres://kiyesi_ro@db.example.com/orders", Password: "credential"})
	if err != nil || s.Password != "s3cret" || s.Kind != LoginEncrypted {
		t.Fatalf("%+v %v", s, err)
	}
	// Made for another database: it does not open.
	if _, err := Decrypt("billing", sealed); err == nil {
		t.Error("a password opened for another database")
	}
	// A different key: it does not open.
	if err := os.WriteFile(KeyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt("orders", sealed); err == nil {
		t.Error("a password opened with another key")
	}
	// No file: the error says where it looked and how to set it up.
	_, err = login(t, Config{Name: "shop", URL: "mysql://kiyesi_ro@db.example.com/shop", Password: "credential"})
	if err == nil || !strings.Contains(err.Error(), "sudo kiyesi databases setup") {
		t.Errorf("missing: %v", err)
	}
}

// Under its service, systemd hands the agent the decrypted password; run by
// hand, systemd-creds decrypts it.
func TestSystemdCredentials(t *testing.T) {
	ownTestStore(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kiyesi.db.orders"), []byte("from-systemd\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	s, err := login(t, Config{Name: "orders", URL: "postgres://kiyesi_ro@db.example.com/orders", Password: "credential"})
	if err != nil || s.Password != "from-systemd" {
		t.Fatalf("%+v %v", s, err)
	}

	t.Setenv("CREDENTIALS_DIRECTORY", "")
	CredstoreDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(CredstoreDir, "kiyesi.db.shop"), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := systemdCreds
	t.Cleanup(func() { systemdCreds = old })
	var asked []string
	systemdCreds = func(_ context.Context, args ...string) ([]byte, error) {
		asked = args
		return []byte("by-systemd-creds\n"), nil
	}
	s, err = login(t, Config{Name: "shop", URL: "mysql://kiyesi_ro@db.example.com/shop", Password: "credential"})
	if err != nil || s.Password != "by-systemd-creds" {
		t.Fatalf("%+v %v", s, err)
	}
	if strings.Join(asked, " ") != "decrypt --name=kiyesi.db.shop "+filepath.Join(CredstoreDir, "kiyesi.db.shop")+" -" {
		t.Errorf("asked systemd-creds %v", asked)
	}
}

// A cloud login is only ever sent inside TLS whose certificate is checked.
func TestCloudLoginsNeedTLS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "role-secret")
	t.Setenv("AWS_SESSION_TOKEN", "role-token")
	for raw, want := range map[string]string{
		"postgres://kiyesi_ro@orders.c9x.eu-west-1.rds.amazonaws.com/orders":                               "sslmode=verify-full",
		"postgres://kiyesi_ro@orders.c9x.eu-west-1.rds.amazonaws.com/orders?sslmode=require":               "sslmode=verify-full",
		"mysql://kiyesi_ro@shop.c9x.eu-west-1.rds.amazonaws.com/shop":                                      "tls=true",
		"redis://kiyesi_ro@cache.example.com:6379":                                                         "rediss://",
		"postgres://kiyesi_ro@10.0.0.5/orders?sslmode=verify-full":                                         "RDS address",
		"mongodb://kiyesi_ro@cluster0.ab1cd.mongodb.net/shop?tls=true":                                     "RDS and Aurora",
		"postgres://kiyesi_ro@orders.c9x.eu-west-1.rds.amazonaws.com/orders?sslmode=verify-full&extra=1#x": "",
	} {
		s, err := login(t, Config{Name: "orders", URL: raw, Password: "aws-iam"})
		if want == "" {
			if err != nil || s.Kind != LoginIAM || !strings.Contains(s.Password, "DBUser=kiyesi_ro") || !strings.Contains(s.Password, "X-Amz-"+"Signature=") {
				t.Errorf("%s: %+v %v", raw, s, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", raw, err, want)
		}
	}
}

// MongoDB's certificate sign-in needs its file, readable by root only.
func TestCertificateLogin(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "shop.pem")
	if err := os.WriteFile(pem, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := "mongodb+srv://cluster0.ab1cd.mongodb.net/shop?authSource=%24external&authMechanism=MONGODB-X509&tlsCertificateKeyFile=" + pem
	if _, err := login(t, Config{Name: "shop", URL: raw}); err == nil || !strings.Contains(err.Error(), "sudo chmod 600 "+pem) {
		t.Errorf("readable by others: %v", err)
	}
	_ = os.Chmod(pem, 0o600)
	if s, err := login(t, Config{Name: "shop", URL: raw}); err != nil || s.Kind != LoginCertificate || s.Password != "" {
		t.Errorf("certificate: %+v %v", s, err)
	}
	if _, err := login(t, Config{Name: "shop", URL: "mongodb+srv://cluster0.ab1cd.mongodb.net/shop?authMechanism=MONGODB-X509"}); err == nil || !strings.Contains(err.Error(), "tlsCertificateKeyFile") {
		t.Errorf("no file: %v", err)
	}
	if s, err := login(t, Config{Name: "shop", URL: "mongodb+srv://cluster0.ab1cd.mongodb.net/shop?authSource=%24external&authMechanism=MONGODB-AWS"}); err != nil || s.Kind != LoginIAM {
		t.Errorf("AWS: %+v %v", s, err)
	}
}

func TestPasswordSettingsNeverEchoed(t *testing.T) {
	for _, setting := range []string{"hunter2", "vault:", "aws-secret:"} {
		_, err := login(t, Config{Name: "orders", URL: "postgres://kiyesi_ro@db.example.com/orders?sslmode=verify-full", Password: setting})
		if err == nil || (setting == "hunter2" && strings.Contains(err.Error(), "hunter2")) {
			t.Errorf("%q: %v", setting, err)
		}
	}
	if _, err := login(t, Config{Name: "orders", URL: "postgres://kiyesi_ro@db.example.com/orders?sslmode=verify-full", Password: "vault:database/creds/kiyesi-ro"}); err == nil || !strings.Contains(err.Error(), "no Vault is set") {
		t.Errorf("no vault: %v", err)
	}
}

// Vault: one sign-in for the reader, a short-lived user's own name used.
func TestVaultLoginGivesItsUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			_, _ = io.WriteString(w, `{"auth":{"client_token":"tok","lease_duration":3600}}`)
		case "/v1/database/creds/kiyesi-ro":
			_, _ = io.WriteString(w, `{"lease_id":"l1","lease_duration":900,"data":{"username":"v-approle-kiyesi-ro-x1","password":"dyn"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	r := &Reader{}
	v := r.VaultFor(cloudlogin.VaultSettings{Address: srv.URL, Auth: "approle", Role: "role-1"})
	v.SecretID = func(context.Context) (string, error) { return "s", nil }
	if r.VaultFor(cloudlogin.VaultSettings{Address: srv.URL, Auth: "approle", Role: "role-1"}) != v {
		t.Error("the same settings give the same Vault")
	}
	s, err := login(t, Config{Name: "orders", URL: "postgres://kiyesi_ro@127.0.0.1/orders", Password: "vault:database/creds/kiyesi-ro", Vault: v})
	if err != nil || s.Kind != LoginVault || s.User != "v-approle-kiyesi-ro-x1" || s.Password != "dyn" {
		t.Errorf("vault: %+v %v", s, err)
	}
}
