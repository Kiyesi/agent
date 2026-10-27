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
	"regexp"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Excess is a right the read-only user has beyond what Kiyesi reads, and
// the commands that take it away, for a person to review and run as the
// database's admin. Kiyesi never uses such a right, but a copy of the
// settings file would give whoever holds it everything the user may do.
type Excess struct {
	// What the right allows, in a sentence.
	What string
	// Why, one sentence each, when What sums up several.
	Details []string
	// NewUser is true when the commands make Kiyesi a user of its own,
	// rather than take rights from the one in the address.
	NewUser bool
	// Where to run the commands, such as "in psql, as an admin".
	Where    string
	Commands []string
}

// Kiyesi's own user is one whose name starts with kiyesi, as the guide
// makes it: taking rights from it is safe. Any other is someone's own
// login, such as the admin or the app's user, which may need them, so the
// advice is a user of Kiyesi's own instead.
func ownUser(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "kiyesi")
}

// ownUserInstead turns what a shared login may do into the commands that
// make Kiyesi a user of its own, with nothing else.
func ownUserInstead(name string, found []Excess, where string, create []string) []Excess {
	details := make([]string, 0, len(found))
	for _, x := range found {
		details = append(details, x.What)
	}
	return []Excess{{
		What: fmt.Sprintf("It signs in as %s, which is not a user of Kiyesi's own. Give Kiyesi one, then put it in the address in the settings; %s keeps its rights.",
			name, name),
		Details:  details,
		NewUser:  true,
		Where:    where,
		Commands: create,
	}}
}

// TooMuch lists the rights the database's user has beyond the smallest
// set Kiyesi needs. It reads only the user's own rights, never a row.
// A database it cannot read, or an engine it cannot ask, gives none.
func TooMuch(ctx context.Context, c Config) []Excess {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	secret, err := LoginFor(ctx, c, u)
	if err != nil {
		return nil
	}
	switch engineOf(u) {
	case "postgresql":
		return postgresExcess(ctx, c.URL, secret.Password)
	case "mysql":
		return mysqlExcess(ctx, u, secret.Password)
	case "mongodb":
		return mongoExcess(ctx, c.URL, secret.Password, u)
	case "redis":
		return redisExcess(ctx, u, secret.Password)
	}
	return nil
}

// PostgreSQL needs only to connect: the size, the connection count and the
// settings are open to every user. pg_read_all_stats (part of pg_monitor)
// shows every session's query text, and a SELECT on a table its rows.
func postgresExcess(ctx context.Context, dsn, password string) []Excess {
	conn, err := connectPostgres(ctx, dsn, password)
	if err != nil {
		return nil
	}
	defer conn.Close(context.Background())
	var user, dbName string
	var super, stats, allData bool
	var schemas []string
	err = conn.QueryRow(ctx, `SELECT quote_ident(current_user), quote_ident(current_database()),
		(SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
		pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER'),
		CASE WHEN to_regrole('pg_read_all_data') IS NULL THEN false
		     ELSE pg_has_role(current_user, to_regrole('pg_read_all_data'), 'MEMBER') END,
		ARRAY(SELECT DISTINCT quote_ident(n.nspname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		      WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f')
		        AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
		        AND has_table_privilege(c.oid, 'SELECT') ORDER BY 1 LIMIT 5)`).
		Scan(&user, &dbName, &super, &stats, &allData, &schemas)
	if err != nil {
		return nil
	}
	where := "in psql, as an admin"
	var out []Excess
	if super {
		out = append(out, Excess{
			What:     "It is a superuser: it can read and change everything.",
			Where:    where,
			Commands: []string{fmt.Sprintf("ALTER ROLE %s NOSUPERUSER;", user)},
		})
		stats, allData, schemas = false, false, nil
	}
	if stats {
		out = append(out, Excess{
			What:     "It is in pg_monitor or pg_read_all_stats, which show the text of every session's queries, with the values in them.",
			Where:    where,
			Commands: []string{fmt.Sprintf("REVOKE pg_monitor, pg_read_all_stats FROM %s;", user)},
		})
	}
	if allData {
		out = append(out, Excess{
			What:     "It is in pg_read_all_data: it can read every table.",
			Where:    where,
			Commands: []string{fmt.Sprintf("REVOKE pg_read_all_data FROM %s;", user)},
		})
	}
	if len(schemas) > 0 {
		cmds := make([]string, 0, len(schemas))
		for _, s := range schemas {
			cmds = append(cmds, fmt.Sprintf("REVOKE SELECT ON ALL TABLES IN SCHEMA %s FROM %s;", s, user))
		}
		out = append(out, Excess{
			What:     "It can read the rows of tables in " + strings.Join(schemas, ", ") + ".",
			Where:    where + ", in this database",
			Commands: cmds,
		})
	}
	if len(out) > 0 && !ownUser(user) {
		return ownUserInstead(user, out, where, []string{
			"CREATE ROLE kiyesi_ro LOGIN CONNECTION LIMIT 3;",
			`\password kiyesi_ro`,
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO kiyesi_ro;", dbName),
		})
	}
	return out
}

var grantLine = regexp.MustCompile(`^GRANT (.+?) ON (\S+) TO `)

// mysqlGrants turns SHOW GRANTS lines into the rights beyond SHOW VIEW on
// one database, the only one Kiyesi needs (to open it and see its tables'
// sizes). A grant of a role, or the password line, is not a right.
func mysqlGrants(lines []string) (global, onDB map[string][]string) {
	global, onDB = map[string][]string{}, map[string][]string{}
	for _, l := range lines {
		m := grantLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		var privs []string
		for _, p := range strings.Split(m[1], ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p == "" || p == "USAGE" || (p == "SHOW VIEW" && m[2] != "*.*") {
				continue
			}
			privs = append(privs, p)
		}
		if len(privs) == 0 {
			continue
		}
		if m[2] == "*.*" {
			global[m[2]] = append(global[m[2]], privs...)
		} else {
			onDB[m[2]] = append(onDB[m[2]], privs...)
		}
	}
	return global, onDB
}

func mysqlExcess(ctx context.Context, u *url.URL, password string) []Excess {
	cfg := mysqlConfig(u, password)
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil
	}
	defer db.Close()
	// The account it signed in as, and the address the server saw it come from.
	var who, from string
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER(), SUBSTRING_INDEX(USER(), '@', -1)").Scan(&who, &from) != nil {
		return nil
	}
	rows, err := db.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var l string
		if rows.Scan(&l) == nil {
			lines = append(lines, l)
		}
	}
	name, host, _ := strings.Cut(who, "@")
	account := fmt.Sprintf("'%s'@'%s'", name, host)
	where := "in mysql (or mariadb), as an admin"
	global, onDB := mysqlGrants(lines)
	var out []Excess
	if p := global["*.*"]; len(p) > 0 {
		what := "It has " + strings.Join(p, ", ") + " on every database"
		if slices.Contains(p, "PROCESS") {
			what += ": PROCESS shows the text of everyone's running queries, with the values in them"
		}
		out = append(out, Excess{
			What:     what + ".",
			Where:    where,
			Commands: []string{fmt.Sprintf("REVOKE %s ON *.* FROM %s;", strings.Join(p, ", "), account)},
		})
	}
	dbs := make([]string, 0, len(onDB))
	for d := range onDB {
		dbs = append(dbs, d)
	}
	slices.Sort(dbs)
	for _, d := range dbs {
		out = append(out, Excess{
			What:     fmt.Sprintf("It has %s on %s, where Kiyesi needs only SHOW VIEW.", strings.Join(onDB[d], ", "), d),
			Where:    where,
			Commands: []string{fmt.Sprintf("REVOKE %s ON %s FROM %s;", strings.Join(onDB[d], ", "), d, account)},
		})
	}
	if host == "%" && from != "" {
		out = append(out, Excess{
			What:     fmt.Sprintf("It may sign in from any address, and the agent connects only from %s.", from),
			Where:    where,
			Commands: []string{fmt.Sprintf("RENAME USER %s TO '%s'@'%s';", account, name, from)},
		})
	}
	if len(out) > 0 && !ownUser(name) {
		to := from
		if to == "" {
			to = "localhost"
		}
		return ownUserInstead(name, out, where, []string{
			fmt.Sprintf("CREATE USER 'kiyesi_ro'@'%s' IDENTIFIED BY 'CHOOSE-A-PASSWORD' WITH MAX_USER_CONNECTIONS 3;", to),
			fmt.Sprintf("GRANT SHOW VIEW ON `%s`.* TO 'kiyesi_ro'@'%s';", cfg.DBName, to),
		})
	}
	return out
}

// mongoNeeds is everything Kiyesi asks MongoDB for (buildInfo needs no right).
var mongoNeeds = []string{"dbStats", "serverStatus"}

func mongoExcess(ctx context.Context, uri, password string, u *url.URL) []Excess {
	client, err := mongo.Connect(mongoOptions(uri, password).SetServerSelectionTimeout(10 * time.Second))
	if err != nil {
		return nil
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	var st struct {
		AuthInfo struct {
			Users []struct {
				User string `bson:"user"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUsers"`
			Roles []struct {
				Role string `bson:"role"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUserRoles"`
			Privileges []struct {
				Actions []string `bson:"actions"`
			} `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	cmd := bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}
	if client.Database("admin").RunCommand(ctx, cmd).Decode(&st) != nil || len(st.AuthInfo.Users) == 0 {
		return nil
	}
	extra := map[string]bool{}
	for _, p := range st.AuthInfo.Privileges {
		for _, a := range p.Actions {
			if !slices.Contains(mongoNeeds, a) {
				extra[a] = true
			}
		}
	}
	if len(extra) == 0 {
		return nil
	}
	var roles []string
	for _, r := range st.AuthInfo.Roles {
		roles = append(roles, r.Role+" on "+r.DB)
	}
	what := "Its roles (" + strings.Join(roles, ", ") + ") allow more than dbStats and serverStatus"
	switch {
	case extra["find"]:
		what += ": it can read documents"
	case extra["inprog"]:
		what += ": it can see everyone's running operations, with the values in them"
	}
	user := st.AuthInfo.Users[0]
	role := fmt.Sprintf(`db.getSiblingDB("admin").createRole({ role: "kiyesiStats", privileges: [{ resource: { db: %q, collection: "" }, actions: ["dbStats"] }, { resource: { cluster: true }, actions: ["serverStatus"] }], roles: [] })`, dbOf(uri))
	where := "in mongosh, as an admin"
	found := []Excess{{What: what + "."}}
	// Atlas undoes roles made in mongosh: they are made with its own tools.
	if strings.HasSuffix(u.Hostname(), ".mongodb.net") {
		who := user.User
		if !ownUser(who) {
			who = "a new user of Kiyesi's own (keep " + user.User + " for what uses it)"
		}
		found[0].Where = "with the Atlas CLI; then, in Atlas under Database Access, give " + who + " only the kiyesiStats role"
		found[0].Commands = []string{fmt.Sprintf("atlas customDbRoles create kiyesiStats --privilege DB_STATS@%s,SERVER_STATUS", dbOf(uri))}
		found[0].NewUser = !ownUser(user.User)
		return found
	}
	if !ownUser(user.User) {
		return ownUserInstead(user.User, found, where, []string{
			role,
			`db.getSiblingDB("admin").createUser({ user: "kiyesi_ro", pwd: passwordPrompt(), roles: [{ role: "kiyesiStats", db: "admin" }] })`,
		})
	}
	found[0].Where = where
	found[0].Commands = []string{
		role,
		fmt.Sprintf(`db.getSiblingDB(%q).updateUser(%q, { roles: [{ role: "kiyesiStats", db: "admin" }] })`, user.DB, user.User),
	}
	return found
}

func dbOf(uri string) string {
	if d, err := connstringDB(uri); err == nil && d != "" {
		return d
	}
	return "test"
}

// Redis and Valkey need only INFO and PING. CONFIG GET shows every setting,
// the main password among them, and a read command a key's value.
func redisExcess(ctx context.Context, u *url.URL, password string) []Excess {
	user := u.User.Username()
	if user == "" || user == "default" {
		what := "With the main password, it can read and change everything."
		if password == "" {
			what = "With no password, anyone who reaches it can read and change everything."
		}
		return ownUserInstead("the default user", []Excess{{What: what}}, "in redis-cli (or valkey-cli), as an admin",
			[]string{"ACL SETUSER kiyesi_ro on >CHOOSE-A-PASSWORD -@all +info +ping"})
	}
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
		return nil
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	rd := bufio.NewReader(conn)
	if password != "" {
		if _, err := command(conn, rd, "AUTH", user, password); err != nil {
			return nil
		}
	}
	// Refused, or not there at all (a command renamed or turned off in the
	// server's settings), is not allowed; any other answer is.
	allowed := func(args ...string) bool {
		_, err := command(conn, rd, args...)
		if err == nil {
			return true
		}
		var nerr net.Error
		if errors.As(err, &nerr) || errors.Is(err, io.EOF) {
			return false
		}
		msg := err.Error()
		return !strings.HasPrefix(msg, "NOPERM") && !strings.HasPrefix(msg, "ERR unknown command")
	}
	var what []string
	if allowed("CONFIG", "GET", "maxclients") {
		what = append(what, "CONFIG GET shows every setting, the main password among them")
	}
	// A key no one uses: the answer is only allowed or not.
	if allowed("GET", "kiyesi:rights-check") {
		what = append(what, "it can read keys' values")
	}
	if allowed("SLOWLOG", "GET", "0") {
		what = append(what, "SLOWLOG shows slow commands with their values")
	}
	if len(what) == 0 {
		return nil
	}
	found := []Excess{{
		What:     "It may run more than INFO and PING: " + strings.Join(what, "; ") + ".",
		Where:    "in redis-cli (or valkey-cli), as an admin",
		Commands: []string{fmt.Sprintf("ACL SETUSER %s -@all +info +ping", user)},
	}}
	if !ownUser(user) {
		return ownUserInstead(user, found, found[0].Where, []string{"ACL SETUSER kiyesi_ro on >CHOOSE-A-PASSWORD -@all +info +ping"})
	}
	return found
}
