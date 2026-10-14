package dbwatch

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// PostgreSQL: the database's size, and connections against max_connections.
func readPostgres(ctx context.Context, dsn string, f *Figures) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var version string
	var size, used, max int64
	err = conn.QueryRow(ctx, `SELECT current_setting('server_version'),
		pg_database_size(current_database()),
		(SELECT count(*) FROM pg_stat_activity),
		current_setting('max_connections')::bigint`).Scan(&version, &size, &used, &max)
	if err != nil {
		return err
	}
	f.Version = strings.Fields(version)[0]
	f.SizeBytes, f.Connections, f.MaxConnections = i64(size), i64(used), i64(max)
	return nil
}

// MySQL and MariaDB: the schema's size, connections, and the server's own
// slow-query counter, turned into a count for the last hour.
func (r *Reader) readMySQL(ctx context.Context, name string, u *url.URL, f *Figures, now time.Time) error {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = u.Host
	if u.Port() == "" {
		cfg.Addr = net.JoinHostPort(u.Hostname(), "3306")
	}
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.Timeout = 10 * time.Second
	if u.Query().Get("tls") == "true" {
		cfg.TLSConfig = "true"
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	var version string
	var size sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT VERSION(),
		(SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = DATABASE())`).Scan(&version, &size); err != nil {
		return err
	}
	f.Version = version
	if size.Valid {
		f.SizeBytes = i64(size.Int64)
	}
	status := func(q string) (int64, error) {
		var k string
		var v int64
		err := db.QueryRowContext(ctx, q).Scan(&k, &v)
		return v, err
	}
	if v, err := status("SHOW GLOBAL STATUS LIKE 'Threads_connected'"); err == nil {
		f.Connections = i64(v)
	}
	if v, err := status("SHOW VARIABLES LIKE 'max_connections'"); err == nil {
		f.MaxConnections = i64(v)
	}
	if v, err := status("SHOW GLOBAL STATUS LIKE 'Slow_queries'"); err == nil {
		if r.slow == nil {
			r.slow = map[string]counter{}
		}
		if last, ok := r.slow[name]; ok && v >= last.value && now.Sub(last.at) > 0 {
			per := float64(v-last.value) * float64(time.Hour) / float64(now.Sub(last.at))
			f.SlowLastHour = i64(int64(per + 0.5))
		}
		r.slow[name] = counter{at: now, value: v}
	}
	return nil
}

// MongoDB: the database's storage (dbStats), and connections where the
// plan allows serverStatus.
func readMongo(ctx context.Context, uri string, f *Figures) error {
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(15 * time.Second).SetAppName("kiyesi-agent"))
	if err != nil {
		return err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}
	cs, err := connstringDB(uri)
	if err != nil {
		return err
	}
	db := client.Database(cs)
	var stats struct {
		StorageSize float64 `bson:"storageSize"`
		IndexSize   float64 `bson:"indexSize"`
		DataSize    float64 `bson:"dataSize"`
	}
	if err := db.RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&stats); err != nil {
		return err
	}
	f.SizeBytes = i64(int64(stats.StorageSize + stats.IndexSize))
	var build struct {
		Version string `bson:"version"`
	}
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&build); err == nil {
		f.Version = build.Version
	}
	var status struct {
		Connections struct {
			Current   int64 `bson:"current"`
			Available int64 `bson:"available"`
		} `bson:"connections"`
	}
	// Shared hosted plans may refuse serverStatus; the size is enough then.
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&status); err == nil {
		f.Connections = i64(status.Connections.Current)
		f.MaxConnections = i64(status.Connections.Current + status.Connections.Available)
	}
	return nil
}

func connstringDB(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return "", errors.New("name the database in the address, such as mongodb+srv://…/catalogue")
	}
	return db, nil
}

// Redis and Valkey: memory against maxmemory, clients, and the slow log's
// entries in the last hour. A few commands over the wire: no driver needed.
func readRedis(ctx context.Context, u *url.URL, f *Figures, now time.Time) error {
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "6379")
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if u.Scheme == "rediss" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	rd := bufio.NewReader(conn)
	if pass, ok := u.User.Password(); ok {
		args := []string{"AUTH", pass}
		if user := u.User.Username(); user != "" && user != "default" {
			args = []string{"AUTH", user, pass}
		}
		if _, err := command(conn, rd, args...); err != nil {
			return err
		}
	}
	info, err := command(conn, rd, "INFO")
	if err != nil {
		return err
	}
	text, _ := info.(string)
	field := func(k string) (int64, bool) {
		for _, line := range strings.Split(text, "\r\n") {
			if v, ok := strings.CutPrefix(line, k+":"); ok {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				return n, err == nil
			}
		}
		return 0, false
	}
	for _, line := range strings.Split(text, "\r\n") {
		if v, ok := strings.CutPrefix(line, "redis_version:"); ok {
			f.Version = v
		} else if v, ok := strings.CutPrefix(line, "valkey_version:"); ok {
			f.Version = v
		}
	}
	if v, ok := field("used_memory"); ok {
		f.SizeBytes = i64(v)
	}
	if v, ok := field("maxmemory"); ok && v > 0 {
		f.LimitBytes, f.LimitSource = i64(v), "maxmemory"
	}
	if v, ok := field("connected_clients"); ok {
		f.Connections = i64(v)
	}
	if cfg, err := command(conn, rd, "CONFIG", "GET", "maxclients"); err == nil {
		if arr, ok := cfg.([]any); ok && len(arr) == 2 {
			if s, ok := arr[1].(string); ok {
				if n, err := strconv.ParseInt(s, 10, 64); err == nil {
					f.MaxConnections = i64(n)
				}
			}
		}
	}
	// The slow log's entries that started in the last hour.
	if slow, err := command(conn, rd, "SLOWLOG", "GET", "128"); err == nil {
		if arr, ok := slow.([]any); ok {
			n := int64(0)
			for _, e := range arr {
				if entry, ok := e.([]any); ok && len(entry) > 1 {
					if ts, ok := entry[1].(int64); ok && now.Unix()-ts <= 3600 {
						n++
					}
				}
			}
			f.SlowLastHour = &n
		}
	}
	return nil
}

// command sends one command and reads its reply (RESP2).
func command(conn net.Conn, rd *bufio.Reader, args ...string) (any, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return reply(rd, 0)
}

func reply(rd *bufio.Reader, depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("reply nested too deeply")
	}
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return nil, errors.New("empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, errors.New(line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 {
			return nil, err
		}
		if n > 4<<20 {
			return nil, errors.New("reply too large")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 {
			return nil, err
		}
		if n > 10000 {
			return nil, errors.New("reply too large")
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := reply(rd, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown reply %q", line[:1])
}
