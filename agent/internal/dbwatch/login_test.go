package dbwatch

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
