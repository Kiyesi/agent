// Package dbwatch reads a database's size, connections and slow queries
// with a read-only user (PRD feature 24). It never reads a row, and the
// database's address and password never leave this server: only the
// figures below are sent.
package dbwatch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Figures are what one database looks like now.
type Figures struct {
	Name           string `json:"name"`
	Engine         string `json:"engine"` // postgresql, mysql, mongodb or redis
	Version        string `json:"version,omitempty"`
	Hosted         bool   `json:"hosted"`
	SizeBytes      *int64 `json:"size_bytes,omitempty"`
	LimitBytes     *int64 `json:"limit_bytes,omitempty"`
	LimitSource    string `json:"limit_source,omitempty"` // plan, disk or maxmemory
	Connections    *int64 `json:"connections,omitempty"`
	MaxConnections *int64 `json:"max_connections,omitempty"`
	// SlowLastHour is the slow queries in the last hour, where the database
	// counts them itself (MySQL, Redis). For the others Kiyesi counts the
	// slow-query lines in the server's logs.
	SlowLastHour   *int64 `json:"slow_last_hour,omitempty"`
	NewestBackupAt string `json:"newest_backup_at,omitempty"`
	// Login is how the agent signs in: socket, encrypted or none. Never
	// the password, nor where it is kept.
	Login string `json:"login,omitempty"`
	// Provider names the service a hosted database is on, such as MongoDB
	// Atlas, from its host name. Never the host itself.
	Provider string `json:"provider,omitempty"`
	// Error says why the database could not be read, in one sentence.
	Error string `json:"error,omitempty"`
}

// Config is one database from the settings file.
type Config struct {
	Name, URL, Limit, Backups string
	// Password names where its password is kept ("credential"), never
	// the password itself.
	Password string
}

// NamePattern is what a database's name may be.
var NamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ParseLimit reads "512MB", "25 GB", "1.5TB" or a plain number of bytes.
func ParseLimit(s string) (int64, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if s == "" {
		return 0, nil
	}
	mult := map[string]float64{"TB": 1 << 40, "GB": 1 << 30, "MB": 1 << 20, "KB": 1 << 10, "B": 1}
	for _, u := range []string{"TB", "GB", "MB", "KB", "B"} {
		if n, ok := strings.CutSuffix(s, u); ok {
			f, err := strconv.ParseFloat(n, 64)
			if err != nil || f <= 0 {
				break
			}
			return int64(f * mult[u]), nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		return n, nil
	}
	return 0, fmt.Errorf("%q is not a size: write it as 512MB or 25GB", s)
}

func engineOf(u *url.URL) string {
	switch u.Scheme {
	case "postgres", "postgresql":
		return "postgresql"
	case "mysql":
		return "mysql"
	case "mongodb", "mongodb+srv":
		return "mongodb"
	case "redis", "rediss":
		return "redis"
	}
	return ""
}

// providers name hosted database services by the end of their host names.
var providers = []struct{ suffix, name string }{
	{".mongodb.net", "MongoDB Atlas"},
	{".rds.amazonaws.com", "AWS RDS"},
	{".supabase.co", "Supabase"},
	{".supabase.com", "Supabase"},
	{".neon.tech", "Neon"},
	{".ondigitalocean.com", "DigitalOcean"},
	{".database.azure.com", "Azure Database"},
	{".psdb.cloud", "PlanetScale"},
	{".upstash.io", "Upstash"},
	{".aivencloud.com", "Aiven"},
	{".redis-cloud.com", "Redis Cloud"},
	{".redislabs.com", "Redis Cloud"},
	{".cache.amazonaws.com", "AWS ElastiCache"},
}

// ProviderOf names the service a hosted database's host belongs to, or ""
// when it is not one Kiyesi knows.
func ProviderOf(host string) string {
	h := strings.ToLower(host)
	for _, p := range providers {
		if strings.HasSuffix(h, p.suffix) {
			return p.name
		}
	}
	return ""
}

// local says whether a host is this server: the database's disk is then
// this server's disk.
func local(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// Reader keeps what one reading needs from the last, such as MySQL's
// slow-query counter, to give a count per hour.
type Reader struct {
	// DiskBytes is the size of the disk holding the databases on this
	// server, from the agent's own measurements.
	DiskBytes func(path string) (int64, bool)
	slow      map[string]counter
}

type counter struct {
	at    time.Time
	value int64
}

// Read reads one database. It never returns an error: a database that
// cannot be read says why in its figures.
func (r *Reader) Read(ctx context.Context, c Config, now time.Time) Figures {
	f := Figures{Name: c.Name}
	u, err := url.Parse(c.URL)
	if err != nil || engineOf(u) == "" {
		f.Error = "The address is not one Kiyesi reads: use postgres://, mysql://, mongodb://, mongodb+srv:// or redis://."
		return f
	}
	f.Engine = engineOf(u)
	f.Hosted = u.Scheme == "mongodb+srv" || !local(u.Hostname())
	if f.Hosted {
		f.Provider = ProviderOf(u.Hostname())
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	secret, err := LoginFor(ctx, c, u)
	if err != nil {
		f.Error = "It was not read: " + err.Error()
		return f
	}
	f.Login = secret.Kind
	switch f.Engine {
	case "postgresql":
		err = readPostgres(ctx, c.URL, secret.Password, &f)
	case "mysql":
		err = r.readMySQL(ctx, c.Name, u, secret.Password, &f, now)
	case "mongodb":
		err = readMongo(ctx, c.URL, secret.Password, &f)
	case "redis":
		err = readRedis(ctx, u, secret.Password, &f, now)
	}
	if err != nil {
		f.Error = plainError(err)
		// The read-only user is made in the admin database, which a
		// mongodb:// address uses only when it says so (mongodb+srv does).
		if f.Engine == "mongodb" && u.Scheme == "mongodb" && u.Query().Get("authSource") == "" &&
			strings.HasPrefix(f.Error, "It refused the read-only user") {
			f.Error += " A user made in the admin database needs ?authSource=admin at the end of the address."
		}
	}
	if limit, perr := ParseLimit(c.Limit); perr == nil && limit > 0 {
		f.LimitBytes, f.LimitSource = &limit, "plan"
	} else if f.LimitBytes == nil && !f.Hosted && f.Engine != "redis" && r.DiskBytes != nil {
		if disk, ok := r.DiskBytes("/var/lib"); ok {
			f.LimitBytes, f.LimitSource = &disk, "disk"
		}
	}
	if c.Backups != "" {
		if at, ok := newest(c.Backups); ok {
			f.NewestBackupAt = at.UTC().Format(time.RFC3339)
		}
	}
	return f
}

// plainError says why a database could not be read, without its address.
func plainError(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout"):
		return "It did not answer within 20 seconds."
	// MySQL's "Access denied … to database": the user may sign in, not open it.
	case strings.Contains(msg, "Error 1044"):
		return "The read-only user may not open this database: give it SHOW VIEW on it."
	// A wrong password first: drivers also mention other addresses they tried.
	case strings.Contains(strings.ToLower(msg), "auth") || strings.Contains(msg, "password") || strings.Contains(msg, "Access denied"):
		return "It refused the read-only user's name or password."
	case strings.Contains(msg, "refused"):
		return "It refused the connection: is it running, and listening where the address says?"
	case strings.Contains(msg, "no such host"):
		return "Its name could not be looked up."
	}
	// Never the address: it may hold a password.
	return "It could not be read: " + redact(msg)
}

var credentials = regexp.MustCompile(`[a-z+]+://[^\s@/]*@`)

func redact(s string) string {
	s = credentials.ReplaceAllString(s, "…://…@")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// newest is the time of the newest file in a backups folder, two levels deep.
func newest(dir string) (time.Time, bool) {
	var best time.Time
	root := filepath.Clean(dir)
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.Count(strings.TrimPrefix(p, root), string(os.PathSeparator)) >= 2 {
				return filepath.SkipDir
			}
			return nil
		}
		if info, err := d.Info(); err == nil && info.ModTime().After(best) {
			best = info.ModTime()
		}
		return nil
	})
	return best, !best.IsZero()
}

func i64(v int64) *int64 { return &v }
