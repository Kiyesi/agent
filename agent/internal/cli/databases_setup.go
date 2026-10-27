package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/dbwatch"
)

// What the setup steps look at on this server. Tests replace them.
var (
	// systemdVersion is the major version of systemd, 0 when there is none.
	systemdVersion = func() int {
		out, err := exec.Command("systemctl", "--version").Output() // #nosec G204 -- systemd's own tool, fixed arguments
		if err != nil {
			return 0
		}
		m := regexp.MustCompile(`systemd (\d+)`).FindSubmatch(out)
		if m == nil {
			return 0
		}
		n, _ := strconv.Atoi(string(m[1]))
		return n
	}
	// fileThere says whether a file (such as a database's socket) exists.
	fileThere = func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
)

// Where each database keeps its socket on Debian and Ubuntu, and others.
var (
	postgresSockets = []string{"/var/run/postgresql", "/run/postgresql", "/tmp"}
	mysqlSockets    = []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock", "/tmp/mysql.sock"}
)

var dbNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_$-]{0,62}$`)

func newDatabasesSetup(io IO) *cobra.Command {
	var host string
	var port int
	cmd := &cobra.Command{
		Use:   "setup [postgres|mysql|mariadb|mongodb|redis] [database]",
		Short: "Print the steps to watch a database, read-only and with no password in a file",
		Long: "Prints numbered steps for this server, for you to review and run: a user for Kiyesi\n" +
			"that may only read sizes and counts, never a row, and cannot write; how it signs\n" +
			"in (through the socket with no password, or with a random password nobody sees,\n" +
			"kept encrypted); and the lines for /etc/kiyesi/config.yaml. Kiyesi changes nothing.\n" +
			"With no engine, it lists the databases it finds on this server.",
		Example: "  sudo kiyesi databases setup\n" +
			"  sudo kiyesi databases setup postgres orders\n" +
			"  sudo kiyesi databases setup mysql shop --host db.internal",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				listLocalDatabases(io.Out)
				return nil
			}
			engine := strings.ToLower(args[0])
			db := "app"
			if len(args) == 2 {
				db = args[1]
			}
			if !dbNamePattern.MatchString(db) {
				return usageErr("%q is not a database name Kiyesi can put in a command: letters, digits, _, $ and -", db)
			}
			if host != "" && !regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`).MatchString(host) {
				return usageErr("%q is not a host name", host)
			}
			s := setupFor{out: io.Out, db: db, host: host, port: port, systemd: systemdVersion()}
			switch engine {
			case "postgres", "postgresql":
				s.postgres()
			case "mysql":
				s.mysql(false)
			case "mariadb":
				s.mysql(true)
			case "mongodb", "mongo":
				s.mongodb()
			case "redis", "valkey":
				s.redis()
			default:
				return usageErr("%q is not an engine Kiyesi watches: postgres, mysql, mariadb, mongodb or redis", engine)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the database's host, when it is not on this server")
	cmd.Flags().IntVar(&port, "port", 0, "the database's port, when it is not the usual one")
	return cmd
}

// listLocalDatabases names the databases whose sockets are on this server.
func listLocalDatabases(out io.Writer) {
	found := 0
	say := func(name, cmd string) {
		found++
		fmt.Fprintf(out, "  %-10s sudo kiyesi databases setup %s <database>\n", name, cmd)
	}
	fmt.Fprintln(out, "On this server:")
	for _, d := range postgresSockets {
		if fileThere(d + "/.s.PGSQL.5432") {
			say("PostgreSQL", "postgres")
			break
		}
	}
	for _, s := range mysqlSockets {
		if fileThere(s) {
			if fileThere("/usr/sbin/mariadbd") {
				say("MariaDB", "mariadb")
			} else {
				say("MySQL", "mysql")
			}
			break
		}
	}
	if fileThere("/usr/bin/mongod") || fileThere("/var/run/mongodb") {
		say("MongoDB", "mongodb")
	}
	if fileThere("/usr/bin/redis-server") || fileThere("/usr/bin/valkey-server") {
		say("Redis", "redis")
	}
	if found == 0 {
		fmt.Fprintln(out, "  none found. For one elsewhere: sudo kiyesi databases setup <engine> <database> --host <host>")
		return
	}
	fmt.Fprintln(out, "\nFor one on another host, add --host <host>.")
}

type setupFor struct {
	out     io.Writer
	db      string
	host    string
	port    int
	systemd int
	step    int
}

func (s *setupFor) intro(what string) {
	fmt.Fprintf(s.out, "Steps to watch %s.\n", what)
	fmt.Fprintln(s.out, "Kiyesi changes nothing: review each step and run it yourself.")
}

// say prints the next numbered step, its commands indented below it.
func (s *setupFor) say(what string, commands ...string) {
	s.step++
	fmt.Fprintf(s.out, "\n%d. %s\n", s.step, what)
	for _, c := range commands {
		for _, line := range strings.Split(c, "\n") {
			fmt.Fprintf(s.out, "     %s\n", line)
		}
	}
}

func (s *setupFor) config(url string, encrypted bool) {
	lines := "databases:\n  - name: " + s.db + "\n    url: " + url
	if encrypted {
		lines += "\n    password: credential"
	}
	s.say("Add it to /etc/kiyesi/config.yaml (the address holds no password):", lines)
	s.say("Check it: Kiyesi signs in the way the agent will, and says how, and any right its user should not have.",
		"sudo kiyesi databases check")
	fmt.Fprintln(s.out, "\nThe agent reads it again within 5 minutes. Guide: https://docs.kiyesi.dev/guides/databases/")
}

// sqlLines writes SQL lines for a printf format inside double quotes: each
// line ends in \n, and what the shell would read there (a double quote,
// MySQL's backquotes around a name, a dollar) is escaped, so the shell
// passes the SQL as written and runs nothing from it.
func sqlLines(sql string) string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
	var b strings.Builder
	for _, l := range strings.Split(sql, "\n") {
		b.WriteString(esc.Replace(l) + `\n`)
	}
	return b.String()
}

// randomPassword makes a password nobody sees: it is set on the database and
// encrypted on this server in one go, never typed, shown or kept in history.
const randomPassword = `pw="$(openssl rand -base64 32 | tr -d '/+=')"` // #nosec G101 -- the shell line that makes a random password, not a password

// store is the commands that keep the password in $pw encrypted for this
// database, then forget it.
func (s *setupFor) store() string {
	if s.systemd >= 254 {
		return "sudo install -d -m 700 " + dbwatch.CredstoreDir + "\n" +
			`printf '%s' "$pw" | sudo systemd-creds encrypt - ` + dbwatch.CredstoreDir + "/" + dbwatch.CredentialPrefix + s.db + "\n" +
			"unset pw"
	}
	return "sudo install -d -m 700 " + dbwatch.OwnCredentialsDir + "\n" +
		`printf '%s' "$pw" | sudo kiyesi databases encrypt ` + s.db + " | sudo tee " + dbwatch.OwnCredentialsDir + "/" + s.db + ".enc >/dev/null\n" +
		"unset pw"
}

func (s *setupFor) storeWords() string {
	if s.systemd >= 254 {
		return "Keep it encrypted with systemd-creds (with this server's TPM chip when it has one); systemd hands it only to the agent, in memory:"
	}
	return "Keep it encrypted with Kiyesi's own key (this server's systemd is older than 254), readable by root only:"
}

func (s *setupFor) hostPort(def int) string {
	p := def
	if s.port > 0 {
		p = s.port
	}
	return fmt.Sprintf("%s:%d", s.host, p)
}

const pgRole = "kiyesi_ro LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3"

func (s *setupFor) postgres() {
	socket := ""
	for _, d := range postgresSockets {
		if fileThere(d + "/.s.PGSQL.5432") {
			socket = d
			break
		}
	}
	readOnly := "ALTER ROLE kiyesi_ro SET default_transaction_read_only = on;\n" +
		"GRANT CONNECT ON DATABASE \"" + s.db + "\" TO kiyesi_ro;"
	if s.host == "" && socket != "" {
		s.intro("the PostgreSQL database " + s.db + " on this server, read-only, through its socket with no password")
		s.say("Make Kiyesi's user. It may connect and read sizes and counts, never a row, and every session it opens is read-only:",
			"sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'\nCREATE ROLE "+pgRole+";\n"+readOnly+"\nSQL")
		s.say("Let this server's root user, which runs the agent, sign in as kiyesi_ro through the socket only (peer). The line goes first in pg_hba.conf, which is read top to bottom:",
			`hba="$(sudo -u postgres psql -tAc 'SHOW hba_file')"; ident="$(sudo -u postgres psql -tAc 'SHOW ident_file')"`,
			`echo 'kiyesi  root  kiyesi_ro' | sudo tee -a "$ident" >/dev/null`,
			`sudo sed -i '1i local  `+s.db+`  kiyesi_ro  peer map=kiyesi' "$hba"`,
			`sudo -u postgres psql -c 'SELECT pg_reload_conf()'`)
		s.config("postgres://kiyesi_ro@/"+s.db+"?host="+socket, false)
		return
	}
	where := "the PostgreSQL database " + s.db
	if s.host != "" {
		where += " on " + s.host
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	admin := "sudo -u postgres psql -v ON_ERROR_STOP=1"
	if s.host != "" {
		admin = `psql -v ON_ERROR_STOP=1 "host=` + s.host + ` port=` + strings.Split(s.hostPort(5432), ":")[1] + ` dbname=` + s.db + ` user=<admin> sslmode=verify-full"`
	}
	s.say("Make Kiyesi's user with a random password nobody sees. It may connect and read sizes and counts, never a row, and every session is read-only. Run it as the database's admin:",
		randomPassword,
		`printf "CREATE ROLE `+pgRole+` PASSWORD '%s';\n`+sqlLines(readOnly)+`" "$pw" | `+admin)
	s.say(s.storeWords(), s.store())
	addr := "127.0.0.1:5432"
	if s.host != "" {
		addr = s.hostPort(5432)
	}
	url := "postgres://kiyesi_ro@" + addr + "/" + s.db
	if s.host != "" {
		url += "?sslmode=verify-full"
	}
	s.config(url, true)
}

func (s *setupFor) mysql(maria bool) {
	name, cli := "MySQL", "mysql"
	if maria {
		name, cli = "MariaDB", "mariadb"
	}
	socket := ""
	for _, p := range mysqlSockets {
		if fileThere(p) {
			socket = p
			break
		}
	}
	grant := "GRANT SHOW VIEW ON `" + s.db + "`.* TO 'kiyesi_ro'@'%s';"
	// MySQL's auth_socket can let root sign in as kiyesi_ro; MariaDB's
	// unix_socket only lets a user in under its own name, root, so MariaDB
	// gets an encrypted password.
	if !maria && s.host == "" && socket != "" {
		s.intro("the MySQL database " + s.db + " on this server, read-only, through its socket with no password")
		s.say("Make Kiyesi's user. Only this server's root user, which runs the agent, may sign in as it, and only through the socket (auth_socket). SHOW VIEW on the one database lets it see its tables' sizes, never their rows:",
			"sudo mysql <<'SQL'\nCREATE USER 'kiyesi_ro'@'localhost' IDENTIFIED WITH auth_socket AS 'root' WITH MAX_USER_CONNECTIONS 3;\n"+fmt.Sprintf(grant, "localhost")+"\nSQL")
		fmt.Fprintln(s.out, "   If it says the auth_socket plugin is not loaded: sudo mysql -e \"INSTALL PLUGIN auth_socket SONAME 'auth_socket.so'\"")
		s.config("mysql://kiyesi_ro@localhost/"+s.db+"?socket="+socket, false)
		return
	}
	where := "the " + name + " database " + s.db
	from := "127.0.0.1"
	if s.host != "" {
		where += " on " + s.host
		from = "<this server's address, as the database sees it>"
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	admin := "sudo " + cli
	if s.host != "" {
		admin = cli + " -h " + s.host + " -P " + strings.Split(s.hostPort(3306), ":")[1] + " -u <admin> -p --ssl"
	}
	s.say("Make Kiyesi's user with a random password nobody sees, allowed only from "+from+". SHOW VIEW on the one database lets it see its tables' sizes, never their rows. Run it as the database's admin:",
		randomPassword,
		`printf "CREATE USER 'kiyesi_ro'@'`+from+`' IDENTIFIED BY '%s' WITH MAX_USER_CONNECTIONS 3;\n`+sqlLines(fmt.Sprintf(grant, from))+`" "$pw" | `+admin)
	s.say(s.storeWords(), s.store())
	addr := "127.0.0.1:3306"
	if s.host != "" {
		addr = s.hostPort(3306)
	}
	url := "mysql://kiyesi_ro@" + addr + "/" + s.db
	if s.host != "" {
		url += "?tls=true"
	}
	s.config(url, true)
}

func (s *setupFor) mongodb() {
	where := "the MongoDB database " + s.db
	if s.host != "" {
		where += " on " + s.host
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	if s.host != "" && strings.HasSuffix(s.host, ".mongodb.net") {
		fmt.Fprintln(s.out, "On MongoDB Atlas, roles and users are made in Atlas itself: see https://docs.kiyesi.dev/guides/databases/ (MongoDB Atlas).")
	}
	s.say("Make a role that may only read the database's size and the server's status, and Kiyesi's user with it and a random password nobody sees. Run it with the database's admin:",
		randomPassword,
		`KIYESI_PW="$pw" mongosh --quiet admin -u <admin> --eval '
db.createRole({ role: "kiyesiStats", privileges: [
  { resource: { db: "`+s.db+`", collection: "" }, actions: ["dbStats"] },
  { resource: { cluster: true }, actions: ["serverStatus"] } ], roles: [] });
db.createUser({ user: "kiyesi_ro", pwd: process.env.KIYESI_PW, roles: [{ role: "kiyesiStats", db: "admin" }] })'`)
	s.say(s.storeWords(), s.store())
	addr := "127.0.0.1:27017"
	if s.host != "" {
		addr = s.hostPort(27017)
	}
	s.config("mongodb://kiyesi_ro@"+addr+"/"+s.db+"?authSource=admin", true)
}

func (s *setupFor) redis() {
	where := "Redis or Valkey"
	if s.host != "" {
		where += " on " + s.host
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	s.say("Make Kiyesi's user with a random password nobody sees. It may run only INFO and PING: no key, no value, no setting:",
		randomPassword,
		`printf 'ACL SETUSER kiyesi_ro on >%s -@all +info +ping\n' "$pw" | redis-cli -a <the admin password> --no-auth-warning`)
	s.say(s.storeWords(), s.store())
	addr := "127.0.0.1:6379"
	if s.host != "" {
		addr = s.hostPort(6379)
	}
	scheme := "redis"
	if s.host != "" {
		scheme = "rediss"
	}
	s.config(scheme+"://kiyesi_ro@"+addr, true)
}

func newDatabasesEncrypt(io IO) *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <database>",
		Short: "Encrypt a database's password with Kiyesi's own key, where systemd is older than 254",
		Long: "Reads the password from the terminal without showing it, or from a pipe, and prints\n" +
			"it encrypted (AES-256-GCM, bound to the database's name) for you to save in\n" +
			dbwatch.OwnCredentialsDir + "/<database>.enc. The key is made once, in " + dbwatch.KeyPath + ",\n" +
			"readable by root only. Where systemd is 254 or later, use systemd-creds instead:\n" +
			"sudo kiyesi databases setup gives the steps.",
		Example: "  printf '%s' \"$pw\" | sudo kiyesi databases encrypt orders | sudo tee " + dbwatch.OwnCredentialsDir + "/orders.enc >/dev/null",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !dbwatch.NamePattern.MatchString(args[0]) {
				return usageErr("%q is not a database name in the settings", args[0])
			}
			in := io.In
			if in == nil {
				in = os.Stdin
			}
			var pw []byte
			if f, ok := in.(*os.File); ok && term.IsTerminal(f.Fd()) {
				fmt.Fprintf(io.Err, "Password for %s (not shown): ", args[0])
				b, err := term.ReadPassword(f.Fd())
				fmt.Fprintln(io.Err)
				if err != nil {
					return err
				}
				pw = b
			} else {
				line, err := bufio.NewReader(in).ReadString('\n')
				if err != nil && line == "" {
					return usageErr("no password came in: pipe it in, or run it in a terminal")
				}
				pw = []byte(strings.TrimRight(line, "\r\n"))
			}
			if len(pw) == 0 {
				return usageErr("the password is empty")
			}
			sealed, err := dbwatch.Encrypt(args[0], string(pw))
			if err != nil {
				return err
			}
			fmt.Fprintln(io.Out, sealed)
			return nil
		},
	}
}
