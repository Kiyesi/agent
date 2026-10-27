package cli

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

// What Docker says about this server's containers. Tests replace them.
var (
	// dockerContainers lists the running containers: name and image. The
	// error is Docker's own, when it is installed but cannot be asked.
	dockerContainers = func() ([][2]string, error) {
		path, err := exec.LookPath("docker")
		if err != nil {
			return nil, nil
		}
		out, err := exec.Command(path, "ps", "--format", "{{.Names}}\t{{.Image}}").CombinedOutput() // #nosec G204 -- Docker's own tool, fixed arguments
		if err != nil {
			return nil, fmt.Errorf("%s", strings.TrimSpace(strings.Split(string(out)+"\n", "\n")[0]))
		}
		var list [][2]string
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if name, image, ok := strings.Cut(l, "\t"); ok {
				list = append(list, [2]string{name, image})
			}
		}
		return list, nil
	}
	// dockerEnv is a container's settings, NAME=value lines.
	dockerEnv = func(name string) []string {
		out, err := exec.Command("docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", name).Output() // #nosec G204 -- Docker's own tool; a name Docker listed
		if err != nil {
			return nil
		}
		return strings.Split(string(out), "\n")
	}
	// dockerPublished is where a container's port is published on this
	// server, such as 127.0.0.1:5432 or 0.0.0.0:5432; empty when it is not.
	dockerPublished = func(name string, port int) string {
		out, err := exec.Command("docker", "port", name, fmt.Sprintf("%d/tcp", port)).Output() // #nosec G204 -- Docker's own tool; a checked name
		if err != nil {
			return ""
		}
		return strings.TrimSpace(strings.Split(string(out), "\n")[0])
	}
	// dockerGateway is the address a container sees this server come from.
	dockerGateway = func(name string) string {
		out, err := exec.Command("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}", name).Output() // #nosec G204 -- Docker's own tool; a checked name
		if err != nil {
			return ""
		}
		return strings.Fields(string(out) + " ")[0]
	}
	// appEnvFiles are the settings files apps commonly keep beside them.
	appEnvFiles = func() []string {
		var files []string
		for _, pattern := range []string{"/opt/*/.env", "/srv/*/.env", "/var/www/*/.env", "/opt/*/*/.env"} {
			m, _ := filepath.Glob(pattern)
			files = append(files, m...)
		}
		return files
	}
)

// Where each database keeps its socket on Debian and Ubuntu, and others.
var (
	postgresSockets = []string{"/var/run/postgresql", "/run/postgresql", "/tmp"}
	mysqlSockets    = []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock", "/tmp/mysql.sock"}
)

var (
	dbNamePattern        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_$-]{0,62}$`)
	hostPattern          = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)
	containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

func newDatabasesSetup(io IO) *cobra.Command {
	var host, container string
	var port int
	cmd := &cobra.Command{
		Use:   "setup [postgres|mysql|mariadb|mongodb|redis] [database]",
		Short: "Print the steps to watch a database, read-only and with no password in a file",
		Long: "Prints numbered steps for this server, for you to review and run: a user for Kiyesi\n" +
			"that may only read sizes and counts, never a row, and cannot write; how it signs\n" +
			"in (through the socket with no password, or with a random password nobody sees,\n" +
			"kept encrypted); and the lines for /etc/kiyesi/config.yaml. Kiyesi changes nothing.\n" +
			"With no engine, it lists the databases it finds: on this server, in its Docker\n" +
			"containers, and the hosted ones its apps use (host and engine only, never a password).",
		Example: "  sudo kiyesi databases setup\n" +
			"  sudo kiyesi databases setup postgres orders\n" +
			"  sudo kiyesi databases setup postgres orders --container app-db-1\n" +
			"  sudo kiyesi databases setup mongodb shop --host cluster0.abcde.mongodb.net\n" +
			"  sudo kiyesi databases setup mysql shop --host db.internal",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				listDatabases(io.Out)
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
			if host != "" && !hostPattern.MatchString(host) {
				return usageErr("%q is not a host name", host)
			}
			if container != "" && !containerNamePattern.MatchString(container) {
				return usageErr("%q is not a container name", container)
			}
			if container != "" && host != "" {
				return usageErr("give --container or --host, not both")
			}
			s := setupFor{out: io.Out, db: db, host: host, port: port, container: container, systemd: systemdVersion()}
			if container != "" && !s.reachContainer(engineDefaultPort(engine)) {
				return nil
			}
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
	cmd.Flags().StringVar(&container, "container", "", "the Docker container the database runs in, on this server")
	return cmd
}

func engineDefaultPort(engine string) int {
	switch engine {
	case "postgres", "postgresql":
		return 5432
	case "mysql", "mariadb":
		return 3306
	case "mongodb", "mongo":
		return 27017
	case "redis", "valkey":
		return 6379
	}
	return 0
}

// imageEngine is the engine a container's image runs, from its name.
func imageEngine(image string) string {
	base := image
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base, _, _ = strings.Cut(base, ":")
	base, _, _ = strings.Cut(base, "@")
	switch {
	case strings.Contains(base, "postgres") || strings.Contains(base, "postgis") || strings.Contains(base, "timescale"):
		return "postgres"
	case strings.Contains(base, "mariadb"):
		return "mariadb"
	case strings.Contains(base, "mysql") || strings.Contains(base, "percona"):
		return "mysql"
	case strings.Contains(base, "mongo"):
		return "mongodb"
	case strings.Contains(base, "redis") || strings.Contains(base, "valkey") || strings.Contains(base, "keydb"):
		return "redis"
	}
	return ""
}

// usedDatabase is a database an app on this server uses, from its settings:
// the engine, host and database name only, never a user or password.
type usedDatabase struct{ engine, host, db string }

// databasesIn finds the database addresses in NAME=value settings.
func databasesIn(lines []string) []usedDatabase {
	var found []usedDatabase
	for _, l := range lines {
		_, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			continue
		}
		engine := map[string]string{"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mongodb": "mongodb", "mongodb+srv": "mongodb", "redis": "redis", "rediss": "redis"}[u.Scheme]
		host := u.Hostname()
		if engine == "" || !hostPattern.MatchString(host) {
			continue
		}
		db := strings.TrimPrefix(u.Path, "/")
		if !dbNamePattern.MatchString(db) || engine == "redis" {
			db = "<database>"
		}
		if engine == "redis" {
			db = "cache"
		}
		found = append(found, usedDatabase{engine, host, db})
	}
	return found
}

// provider names a hosted database's service from its host, with what to
// know when setting up its user there.
func provider(host string) (name, note string) {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, ".mongodb.net"):
		return "MongoDB Atlas", ""
	case strings.HasSuffix(h, ".rds.amazonaws.com"):
		return "AWS RDS", "Run the SQL as the database's master user, from a server that can reach it."
	case strings.HasSuffix(h, ".supabase.co") || strings.HasSuffix(h, ".supabase.com"):
		return "Supabase", "Run the SQL in Supabase's SQL Editor (it signs in as postgres)."
	case strings.HasSuffix(h, ".neon.tech"):
		return "Neon", "Run the SQL in Neon's SQL Editor, on the database's branch."
	case strings.HasSuffix(h, ".ondigitalocean.com"):
		return "DigitalOcean", "Run the SQL as doadmin, from a server in the database's trusted sources."
	case strings.HasSuffix(h, ".database.azure.com"):
		return "Azure Database", "Run the SQL as the server's admin user."
	case strings.HasSuffix(h, ".psdb.cloud"):
		return "PlanetScale", "PlanetScale makes passwords in its dashboard, and its smallest role, Reader, can read rows: Kiyesi reads only sizes, but that password could read data."
	case strings.HasSuffix(h, ".upstash.io"):
		return "Upstash", "If Upstash refuses ACL SETUSER, it has no way to make a user that only reads INFO."
	}
	return "", ""
}

// listDatabases names every database it can find for this server: on it,
// in its containers, and those its apps use elsewhere; and how to set up
// one it cannot find.
func listDatabases(out io.Writer) {
	found := 0
	fmt.Fprintln(out, "On this server:")
	local := 0
	say := func(name, cmd string) {
		local++
		fmt.Fprintf(out, "  %-12s sudo kiyesi databases setup %s <database>\n", name, cmd)
	}
	for _, d := range postgresSockets {
		if fileThere(d + "/.s.PGSQL.5432") {
			say("PostgreSQL", "postgres")
			break
		}
	}
	for _, sock := range mysqlSockets {
		if fileThere(sock) {
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
	if local == 0 {
		fmt.Fprintln(out, "  none installed here")
	}
	found += local

	containers, dockerErr := dockerContainers()
	if dockerErr != nil {
		fmt.Fprintf(out, "\nDocker is installed here, but asking it for its containers failed: %v\nRun this as root, and check the Docker service is running (systemctl status docker).\n", dockerErr)
	}
	inContainers := 0
	var used []usedDatabase
	for _, c := range containers {
		if !containerNamePattern.MatchString(c[0]) {
			continue
		}
		if e := imageEngine(c[1]); e != "" {
			if inContainers == 0 {
				fmt.Fprintln(out, "\nIn Docker containers on this server:")
			}
			inContainers++
			fmt.Fprintf(out, "  %-24s sudo kiyesi databases setup %s <database> --container %s\n", c[0], e, c[0])
			continue
		}
		used = append(used, databasesIn(dockerEnv(c[0]))...)
	}
	found += inContainers
	for _, f := range appEnvFiles() {
		b, err := os.ReadFile(f) // #nosec G304 -- an app's settings file under /opt, /srv or /var/www, read for host names only
		if err == nil {
			used = append(used, databasesIn(strings.Split(string(b), "\n"))...)
		}
	}
	seen := map[string]bool{}
	shown := 0
	for _, u := range used {
		key := u.engine + " " + u.host + " " + u.db
		if seen[key] {
			continue
		}
		seen[key] = true
		if shown == 0 {
			fmt.Fprintln(out, "\nUsed by the apps on this server (from their settings: host only, never a password):")
		}
		shown++
		label, _ := provider(u.host)
		if label == "" {
			label = u.host
		} else {
			label += " " + u.host
		}
		fmt.Fprintf(out, "  %s\n    sudo kiyesi databases setup %s %s --host %s\n", label, u.engine, u.db, u.host)
	}
	found += shown
	if found == 0 {
		fmt.Fprintln(out, "\nNo database was found on this server, in its containers, or in its apps' settings.")
	}
	fmt.Fprintln(out, "\nFor any other database:")
	fmt.Fprintln(out, "  In a container here:      sudo kiyesi databases setup <engine> <database> --container <name>")
	fmt.Fprintln(out, "  MongoDB Atlas:            sudo kiyesi databases setup mongodb <database> --host <cluster>.mongodb.net")
	fmt.Fprintln(out, "  Hosted or on another host (AWS RDS, Google Cloud SQL, Azure, Supabase, Neon, DigitalOcean, Upstash...):")
	fmt.Fprintln(out, "                            sudo kiyesi databases setup <engine> <database> --host <host>")
	fmt.Fprintln(out, "  Engines: postgres, mysql, mariadb, mongodb, redis.")
}

type setupFor struct {
	out       io.Writer
	db        string
	host      string
	port      int
	container string
	// addr is where this server reaches the container's database, and
	// openToAll says its port is published on every address.
	addr      string
	openToAll bool
	systemd   int
	step      int
}

func (s *setupFor) intro(what string) {
	fmt.Fprintf(s.out, "Steps to watch %s.\n", what)
	fmt.Fprintln(s.out, "Kiyesi changes nothing: review each step and run it yourself.")
	if _, note := provider(s.host); note != "" {
		fmt.Fprintln(s.out, note)
	}
	if s.openToAll {
		port := s.addr[strings.LastIndex(s.addr, ":")+1:]
		fmt.Fprintf(s.out, "Its port is published on every address of this server, so anyone who reaches the server can try to sign in. Publish it on 127.0.0.1 only, in its compose file: ports: [\"127.0.0.1:%s:%d\"]\n", port, s.port)
	}
}

// reachContainer finds where this server reaches the container's database:
// its port published here. Unpublished, it says how to publish it on
// 127.0.0.1 only and returns false.
func (s *setupFor) reachContainer(port int) bool {
	if port == 0 {
		return true
	}
	published := dockerPublished(s.container, port)
	if published == "" {
		fmt.Fprintf(s.out, "The container %s does not publish port %d on this server, so the agent cannot reach it.\n", s.container, port)
		fmt.Fprintf(s.out, "Publish it on 127.0.0.1 only, so nothing outside the server can reach it. In its compose file:\n\n     ports:\n       - \"127.0.0.1:%d:%d\"\n\nThen run docker compose up -d, and this command again.\n", port, port)
		return false
	}
	hostPort := published[strings.LastIndex(published, ":")+1:]
	s.addr = "127.0.0.1:" + hostPort
	s.port = port
	s.openToAll = !strings.HasPrefix(published, "127.")
	return true
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

// storeTyped is the commands that ask for a password made elsewhere (such
// as Atlas's generated one), without showing it or keeping it in history,
// and keep it encrypted for this database.
func (s *setupFor) storeTyped() string {
	if s.systemd >= 254 {
		return "sudo install -d -m 700 " + dbwatch.CredstoreDir + "\n" +
			`sudo sh -c 'systemd-ask-password "Password for kiyesi_ro (not shown):" | systemd-creds encrypt - ` + dbwatch.CredstoreDir + "/" + dbwatch.CredentialPrefix + s.db + `'`
	}
	return "sudo install -d -m 700 " + dbwatch.OwnCredentialsDir + "\n" +
		`sudo sh -c 'kiyesi databases encrypt ` + s.db + ` > ` + dbwatch.OwnCredentialsDir + "/" + s.db + `.enc'`
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
	if s.container != "" {
		where += " in the container " + s.container
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	admin := "sudo -u postgres psql -v ON_ERROR_STOP=1"
	if s.container != "" {
		admin = `sudo docker exec -i ` + s.container + ` sh -c 'exec psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}"'`
	}
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
	if s.addr != "" {
		addr = s.addr
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
	if !maria && s.host == "" && s.container == "" && socket != "" {
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
	if s.container != "" {
		where += " in the container " + s.container
		// Through the published port, the database sees this server come
		// from its network's gateway.
		if g := dockerGateway(s.container); g != "" {
			from = g
		}
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	admin := "sudo " + cli
	if s.container != "" {
		root := `"$MYSQL_ROOT_PASSWORD"`
		if maria {
			root = `"${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}"`
		}
		admin = `sudo docker exec -i ` + s.container + ` sh -c 'exec ` + cli + ` -uroot -p` + root + `'`
	}
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
	if s.addr != "" {
		addr = s.addr
	}
	url := "mysql://kiyesi_ro@" + addr + "/" + s.db
	if s.host != "" {
		url += "?tls=true"
	}
	s.config(url, true)
}

// mongoUserJS makes the role that may only read the database's size and
// the server's status, and Kiyesi's user with it, its password from the
// environment so it is never in a command line.
func (s *setupFor) mongoUserJS() string {
	return `db.getSiblingDB("admin").createRole({ role: "kiyesiStats", privileges: [
  { resource: { db: "` + s.db + `", collection: "" }, actions: ["dbStats"] },
  { resource: { cluster: true }, actions: ["serverStatus"] } ], roles: [] });
db.getSiblingDB("admin").createUser({ user: "kiyesi_ro", pwd: process.env.KIYESI_PW, roles: [{ role: "kiyesiStats", db: "admin" }] });`
}

func (s *setupFor) mongodb() {
	if strings.HasSuffix(strings.ToLower(s.host), ".mongodb.net") {
		s.atlas()
		return
	}
	where := "the MongoDB database " + s.db
	if s.host != "" {
		where += " on " + s.host
	}
	if s.container != "" {
		where += " in the container " + s.container
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	admin := `KIYESI_PW="$pw" mongosh --quiet admin -u <admin>`
	if s.host != "" {
		admin = `KIYESI_PW="$pw" mongosh --quiet "mongodb://` + s.hostPort(27017) + `/admin?tls=true" -u <admin>`
	}
	if s.container != "" {
		admin = `sudo docker exec -i -e KIYESI_PW="$pw" ` + s.container + ` sh -c 'exec mongosh --quiet admin -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD"'`
	}
	s.say("Make a role that may only read the database's size and the server's status, and Kiyesi's user with it and a random password nobody sees. Run it as the database's admin:",
		randomPassword,
		admin+" <<'JS'\n"+s.mongoUserJS()+"\nJS")
	s.say(s.storeWords(), s.store())
	addr := "127.0.0.1:27017"
	if s.host != "" {
		addr = s.hostPort(27017)
	}
	if s.addr != "" {
		addr = s.addr
	}
	url := "mongodb://kiyesi_ro@" + addr + "/" + s.db + "?authSource=admin"
	if s.host != "" {
		url += "&tls=true"
	}
	s.config(url, true)
}

// atlas is MongoDB Atlas: its roles and users are made in Atlas itself,
// which undoes one made in mongosh. Every plan allows a custom role.
func (s *setupFor) atlas() {
	s.intro("the MongoDB Atlas database " + s.db + " on " + s.host + ", read-only, with a password kept encrypted")
	s.say("In Atlas, make a custom role that may only read the database's size and the server's status. With the Atlas CLI:",
		"atlas customDbRoles create kiyesiStats --privilege DB_STATS@"+s.db+",SERVER_STATUS")
	fmt.Fprintln(s.out, "   Or in Atlas: Database Access, Custom Roles, Add New Custom Role, named kiyesiStats: dbStats on the database "+s.db+", and serverStatus under Global Actions and Roles.")
	s.say("In Atlas, make Kiyesi's user: Database Access, Database Users, Add New Database User. Choose Password, name it kiyesi_ro, choose Autogenerate Secure Password and copy it. Under Database User Privileges, give it only the custom role kiyesiStats, and restrict its access to this cluster.")
	s.say("In Atlas, let only this server reach the cluster: Network Access, Add IP Address, with this server's public address and nothing broader. This shows it:",
		"curl -4s https://checkip.amazonaws.com")
	s.say(strings.Replace(s.storeWords(), ":", ". Paste the password when asked; it is not shown or kept in your history:", 1), s.storeTyped())
	s.config("mongodb+srv://kiyesi_ro@"+s.host+"/"+s.db, true)
	fmt.Fprintln(s.out, "A later release signs in to Atlas with the cloud's own identity, with no password kept at all.")
}

func (s *setupFor) redis() {
	where := "Redis or Valkey"
	if s.host != "" {
		where += " on " + s.host
	}
	if s.container != "" {
		where += " in the container " + s.container
	}
	s.intro(where + ", read-only, with a random password kept encrypted")
	admin := "redis-cli -a <the admin password> --no-auth-warning"
	if s.host != "" {
		admin = "redis-cli --tls -h " + s.host + " -p " + strings.Split(s.hostPort(6379), ":")[1] + " -a <the admin password> --no-auth-warning"
	}
	if s.container != "" {
		admin = `sudo docker exec -i ` + s.container + ` sh -c 'exec "$(command -v redis-cli || command -v valkey-cli)" ${REDIS_PASSWORD:+-a "$REDIS_PASSWORD" --no-auth-warning}'`
	}
	s.say("Make Kiyesi's user with a random password nobody sees. It may run only INFO and PING: no key, no value, no setting:",
		randomPassword,
		`printf 'ACL SETUSER kiyesi_ro on >%s -@all +info +ping\n' "$pw" | `+admin)
	s.say(s.storeWords(), s.store())
	addr := "127.0.0.1:6379"
	if s.host != "" {
		addr = s.hostPort(6379)
	}
	if s.addr != "" {
		addr = s.addr
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
