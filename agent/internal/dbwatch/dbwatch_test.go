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
	if err := readRedis(context.Background(), u, &f, time.Now()); err != nil {
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
		f := r.Read(context.Background(), Config{Name: engine, URL: u}, time.Now())
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
	f := r.Read(context.Background(), Config{Name: "x", URL: bad}, time.Now())
	if !strings.Contains(f.Error, "refused the read-only user") || strings.Contains(f.Error, "wrong") {
		t.Errorf("wrong password: %q", f.Error)
	}
	// The docs' MongoDB user lives in admin: an address that does not say
	// so is told how, and one for another engine is not.
	noSource := strings.Replace(urls["mongodb"], "authSource=admin&", "", 1)
	f = r.Read(context.Background(), Config{Name: "x", URL: noSource}, time.Now())
	if !strings.Contains(f.Error, "needs ?authSource=admin") {
		t.Errorf("mongodb without authSource: %q", f.Error)
	}
	if strings.Contains(r.Read(context.Background(), Config{Name: "x", URL: bad}, time.Now()).Error, "authSource") {
		t.Error("the authSource hint shown for PostgreSQL")
	}
	// An empty MySQL database is 0 bytes, as the other engines say, not unknown.
	f = r.Read(context.Background(), Config{Name: "x", URL: os.Getenv("KIYESI_DB_MYSQL_EMPTY")}, time.Now())
	if f.Error != "" || f.SizeBytes == nil || *f.SizeBytes != 0 {
		t.Errorf("empty mysql: %+v", f)
	}
}

func fmtFigures(f Figures) string {
	return strings.Join([]string{f.Name, f.Version, f.Error, f.NewestBackupAt}, " ")
}
