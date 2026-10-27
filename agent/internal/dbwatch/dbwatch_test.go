package dbwatch

import (
	"bufio"
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/cloudlogin"
)

func TestParseLimit(t *testing.T) {
	for in, want := range map[string]int64{"512MB": 512 << 20, "25 GB": 25 << 30, "1.5TB": 3 << 39, "1024": 1024, "": 0} {
		if got, err := ParseLimit(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	if _, err := ParseLimit("lots"); err == nil {
		t.Error("lots should not parse")
	}
}

func TestErrorsNeverShowTheAddress(t *testing.T) {
	msg := plainError(errorString("dial postgres://kiyesi_ro:s3cret@db.internal:5432/orders: weird failure"))
	if strings.Contains(msg, "s3cret") || strings.Contains(msg, "kiyesi_ro") {
		t.Errorf("leaked: %s", msg)
	}
	if got := plainError(errorString("connect: connection refused")); !strings.HasPrefix(got, "It refused the connection") {
		t.Errorf("refused: %s", got)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func TestLocalOrHosted(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "10.0.0.5": true, "172.18.0.3": true, "cluster0.abc.mongodb.net": false, "203.0.113.9": false} {
		if local(host) != want {
			t.Errorf("%s: local = %v", host, !want)
		}
	}
}

// A fake Redis that answers the few commands the reader sends.
func fakeRedis(t *testing.T) string {
	return fakeRedisWith(t, "# Server\r\nredis_version:7.0.15\r\n# Memory\r\nused_memory:50331648\r\nmaxmemory:268435456\r\n# Clients\r\nconnected_clients:12\r\n")
}

// fakeRedisWith answers INFO with info, and CONFIG GET maxclients with 10000.
func fakeRedisWith(t *testing.T, info string) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rd := bufio.NewReader(c)
		now := time.Now().Unix()
		for {
			v, err := reply(rd, 0)
			if err != nil {
				return
			}
			args, _ := v.([]any)
			switch strings.ToUpper(args[0].(string)) {
			case "AUTH":
				c.Write([]byte("+OK\r\n"))
			case "INFO":
				c.Write([]byte("$" + itoa(len(info)) + "\r\n" + info + "\r\n"))
			case "CONFIG":
				c.Write([]byte("*2\r\n$10\r\nmaxclients\r\n$5\r\n10000\r\n"))
			case "SLOWLOG":
				// Two entries in the last hour, one older.
				entry := func(id int, ts int64) string {
					return "*4\r\n:" + itoa(id) + "\r\n:" + itoa64(ts) + "\r\n:15000\r\n*1\r\n$3\r\nGET\r\n"
				}
				c.Write([]byte("*3\r\n" + entry(3, now-60) + entry(2, now-600) + entry(1, now-7200)))
			}
		}
	}()
	return l.Addr().String()
}

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func TestReadRedisFromItsOwnFigures(t *testing.T) {
	addr := fakeRedis(t)
	u, _ := url.Parse("redis://:pw@" + addr)
	var f Figures
	if err := readRedis(context.Background(), u, Secret{Password: "pw"}, &f, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f.Version != "7.0.15" || *f.SizeBytes != 48<<20 || *f.LimitBytes != 256<<20 || f.LimitSource != "maxmemory" {
		t.Errorf("figures = %+v", f)
	}
	if *f.Connections != 12 || *f.MaxConnections != 10000 || *f.SlowLastHour != 2 {
		t.Errorf("connections and slow = %d %d %d", *f.Connections, *f.MaxConnections, *f.SlowLastHour)
	}
}

func TestNewestBackup(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "a.dump")
	_ = os.WriteFile(old, []byte("x"), 0o600)
	_ = os.Chtimes(old, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	_ = os.MkdirAll(filepath.Join(dir, "daily"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "daily", "b.dump"), []byte("x"), 0o600)
	at, ok := newest(dir)
	if !ok || time.Since(at) > time.Minute {
		t.Errorf("newest = %v %v", at, ok)
	}
}

// Run by scripts/db-watch-test.sh, with real databases in containers.
func TestRealDatabases(t *testing.T) {
	urls := map[string]string{
		"postgresql": os.Getenv("KIYESI_DB_POSTGRES"),
		"mysql":      os.Getenv("KIYESI_DB_MYSQL"),
		"mariadb":    os.Getenv("KIYESI_DB_MARIADB"),
		"mongodb":    os.Getenv("KIYESI_DB_MONGO"),
		"redis":      os.Getenv("KIYESI_DB_REDIS"),
	}
	if urls["postgresql"] == "" {
		t.Skip("run scripts/db-watch-test.sh")
	}
	r := &Reader{DiskBytes: func(string) (int64, bool) { return 50 << 30, true }}
	for engine, u := range urls {
		f := r.Read(context.Background(), viaCredential(t, engine, u), time.Now())
		if f.Error != "" {
			t.Errorf("%s: %s", engine, f.Error)
			continue
		}
		want := engine
		if engine == "mariadb" {
			want = "mysql"
		}
		if f.Engine != want || f.Version == "" || f.SizeBytes == nil || *f.SizeBytes <= 0 {
			t.Errorf("%s: %+v", engine, f)
		}
		if f.Connections == nil || f.MaxConnections == nil || *f.MaxConnections <= 0 {
			t.Errorf("%s: connections %+v", engine, f)
		}
		if engine != "redis" && (f.LimitSource != "disk" || *f.LimitBytes != 50<<30) {
			t.Errorf("%s: a database on this server is measured against its disk: %+v", engine, f)
		}
		// Nothing a table holds ever comes back.
		if strings.Contains(fmtFigures(f), "card-4111") || strings.Contains(fmtFigures(f), "ro-pw") {
			t.Errorf("%s: figures hold a row or the password", engine)
		}
		t.Logf("%s %s: size %d, connections %d of %d", engine, f.Version, *f.SizeBytes, *f.Connections, *f.MaxConnections)
	}
	// A wrong password says so, without the address.
	bad := strings.Replace(urls["postgresql"], "ro-pw", "wrong", 1)
	f := r.Read(context.Background(), viaCredential(t, "x", bad), time.Now())
	if !strings.Contains(f.Error, "refused the read-only user") || strings.Contains(f.Error, "wrong") {
		t.Errorf("wrong password: %q", f.Error)
	}
	// The docs' MongoDB user lives in admin: an address that does not say
	// so is told how, and one for another engine is not.
	noSource := strings.Replace(urls["mongodb"], "authSource=admin&", "", 1)
	f = r.Read(context.Background(), viaCredential(t, "x", noSource), time.Now())
	if !strings.Contains(f.Error, "needs ?authSource=admin") {
		t.Errorf("mongodb without authSource: %q", f.Error)
	}
	if strings.Contains(r.Read(context.Background(), viaCredential(t, "x", bad), time.Now()).Error, "authSource") {
		t.Error("the authSource hint shown for PostgreSQL")
	}
	// An empty MySQL database is 0 bytes, as the other engines say, not unknown.
	f = r.Read(context.Background(), viaCredential(t, "x", os.Getenv("KIYESI_DB_MYSQL_EMPTY")), time.Now())
	if f.Error != "" || f.SizeBytes == nil || *f.SizeBytes != 0 {
		t.Errorf("empty mysql: %+v", f)
	}
}

func fmtFigures(f Figures) string {
	return strings.Join([]string{f.Name, f.Version, f.Error, f.NewestBackupAt}, " ")
}

// viaCredential keeps an address's password the way the agent reads it, in
// Kiyesi's own encrypted file in a test folder, and gives the settings
// without it: a password in an address is refused.
func viaCredential(t *testing.T, name, raw string) Config {
	t.Helper()
	ownTestStore(t)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pw, ok := u.User.Password()
	if !ok {
		return Config{Name: name, URL: raw}
	}
	u.User = url.User(u.User.Username())
	sealed, err := Encrypt(name, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(OwnCredentialsDir, name+".enc"), []byte(sealed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Name: name, URL: u.String(), Password: "credential"}
}

// ownTestStore points Kiyesi's own encrypted passwords at a test folder,
// with no systemd store, once per test.
func ownTestStore(t *testing.T) {
	t.Helper()
	if strings.HasPrefix(OwnCredentialsDir, os.TempDir()) {
		return
	}
	dir, key, store := OwnCredentialsDir, KeyPath, CredstoreDir
	t.Cleanup(func() { OwnCredentialsDir, KeyPath, CredstoreDir = dir, key, store })
	OwnCredentialsDir = t.TempDir()
	KeyPath = filepath.Join(t.TempDir(), "db.key")
	CredstoreDir = filepath.Join(t.TempDir(), "none")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
}

// Run by scripts/db-watch-test.sh: databases whose certificates a private
// authority signs, as AWS RDS, Supabase and DigitalOcean do. Named in the
// address, the authority checks the certificate and the database is read;
// left out, the connection is refused, so the certificate is really checked.
func TestRealPrivateAuthority(t *testing.T) {
	if os.Getenv("KIYESI_TLS_PG") == "" {
		t.Skip("run scripts/db-watch-test.sh")
	}
	ca := os.Getenv("KIYESI_TLS_CA")
	r := &Reader{}
	for _, env := range []string{"KIYESI_TLS_PG", "KIYESI_TLS_MY", "KIYESI_TLS_MO", "KIYESI_TLS_RD"} {
		raw := os.Getenv(env)
		f := r.Read(context.Background(), viaCredential(t, "tls", raw), time.Now())
		if f.Error != "" || f.SizeBytes == nil {
			t.Errorf("%s with its authority: %+v", env, f)
			continue
		}
		without := raw
		for _, p := range []string{"&sslrootcert=" + ca, "&ca=" + ca, "?ca=" + ca, "&tlsCAFile=" + ca} {
			without = strings.Replace(without, p, "", 1)
		}
		if without == raw {
			t.Fatalf("%s: no authority to leave out", env)
		}
		if g := r.Read(context.Background(), viaCredential(t, "tls", without), time.Now()); g.Error == "" {
			t.Errorf("%s was read without its authority: the certificate was not checked", env)
		}
		t.Logf("%s: read with its authority (%s %s), refused without it", env, f.Engine, f.Version)
	}
}

// A real Vault making short-lived read-only users on a real PostgreSQL:
// the agent signs in with an AppRole, reads with Vault's user, renews its
// lease, and takes a new user when the lease can be renewed no more.
func TestRealVault(t *testing.T) {
	addr := os.Getenv("KIYESI_VAULT_ADDR")
	if addr == "" {
		t.Skip("run scripts/db-watch-test.sh")
	}
	r := &Reader{}
	v := r.VaultFor(cloudlogin.VaultSettings{Address: addr, Auth: "approle", Role: os.Getenv("KIYESI_VAULT_ROLE_ID")})
	v.SecretID = func(context.Context) (string, error) { return os.Getenv("KIYESI_VAULT_SECRET_ID"), nil }
	c := Config{Name: "orders", URL: os.Getenv("KIYESI_VAULT_PG"), Password: "vault:database/creds/kiyesi-ro", Vault: v}
	user := func() string {
		t.Helper()
		f := r.Read(context.Background(), c, time.Now())
		if f.Error != "" || f.SizeBytes == nil || f.Login != LoginVault {
			t.Fatalf("read: %+v", f)
		}
		u, _ := url.Parse(c.URL)
		s, err := LoginFor(context.Background(), c, u)
		if err != nil || !strings.HasPrefix(s.User, "v-approle-kiyesi-r") {
			t.Fatalf("its user: %+v %v", s, err)
		}
		return s.User
	}
	first := user()
	// Vault's user has the smallest rights: nothing more than Kiyesi needs.
	if x := TooMuch(context.Background(), c); len(x) > 0 {
		t.Errorf("Vault's user may do more: %+v", x)
	}
	// The role gives 15 seconds, renewable up to 40: at 11 seconds the
	// same user is renewed, after 40 a new one is made.
	time.Sleep(11 * time.Second)
	if again := user(); again != first {
		t.Errorf("renewed: got %s, want the same %s", again, first)
	}
	time.Sleep(32 * time.Second)
	if next := user(); next == first {
		t.Errorf("after its longest time: still %s", first)
	}
	t.Logf("read as %s, renewed, then a new user", first)
}

// A real MongoDB with a certificate sign-in, as Atlas's X.509 users are:
// no password anywhere, and a file readable by root only.
func TestRealCertificate(t *testing.T) {
	raw := os.Getenv("KIYESI_X509_MO")
	if raw == "" {
		t.Skip("run scripts/db-watch-test.sh")
	}
	f := (&Reader{}).Read(context.Background(), Config{Name: "catalogue", URL: raw}, time.Now())
	if f.Error != "" || f.SizeBytes == nil || f.Login != LoginCertificate {
		t.Fatalf("certificate: %+v", f)
	}
	t.Logf("read with a certificate (%s %s)", f.Engine, f.Version)
}
