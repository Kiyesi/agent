package cli

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/config"
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

// What setup reads about this server besides its databases. Tests replace them.
var (
	// setupSettingsPath is Kiyesi's settings file, to add the database to.
	setupSettingsPath = "/etc/kiyesi/config.yaml"
	// hasIPv6 says whether this server has a public IPv6 address, which
	// Supabase's direct connections need.
	hasIPv6 = func() bool {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return false
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return true
			}
		}
		return false
	}
	// publicIPv4 is this server's public address, when it is on one of
	// its network cards (as on DigitalOcean); empty behind a NAT.
	publicIPv4 = func() string {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return ""
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			if _, cgnat, _ := net.ParseCIDR("100.64.0.0/10"); cgnat.Contains(ip) {
				continue
			}
			return ip.String()
		}
		return ""
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
	var host, container, login, vaultAddr, vaultAuth string
	var port int
	cmd := &cobra.Command{
		Use:   "setup [postgres|mysql|mariadb|mongodb|redis] [database]",
		Short: "Print the steps to watch a database, read-only and with no password in a file",
		Long: "Prints numbered steps for this server, for you to review and run: a user for Kiyesi\n" +
			"that may only read sizes and counts, never a row, and cannot write; how it signs\n" +
			"in, the safest way where the database is (through the socket; with a short-lived\n" +
			"token from the server's cloud identity on AWS RDS, Azure and Google Cloud SQL; with\n" +
			"a certificate on MongoDB Atlas; from your vault; or with a random password nobody\n" +
			"sees, kept encrypted); and the lines for /etc/kiyesi/config.yaml. Kiyesi changes nothing.\n" +
			"With no engine, it lists the databases it finds: on this server, in its Docker\n" +
			"containers, and the hosted ones its apps use (host and engine only, never a password).",
		Example: "  sudo kiyesi databases setup\n" +
			"  sudo kiyesi databases setup postgres orders\n" +
			"  sudo kiyesi databases setup postgres orders --container app-db-1\n" +
			"  sudo kiyesi databases setup mongodb shop --host cluster0.abcde.mongodb.net\n" +
			"  sudo kiyesi databases setup postgres orders --host orders.c9x.eu-west-1.rds.amazonaws.com\n" +
			"  sudo kiyesi databases setup postgres orders --host 10.20.0.3 --login gcp-iam\n" +
			"  sudo kiyesi databases setup mysql shop --host db.internal --login vault --vault https://vault.example.com:8200",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var engine, db string
			if len(args) == 0 {
				found := findDatabases()
				one := found.only()
				if one == nil {
					listDatabases(io.Out, found)
					return nil
				}
				// One database, and all its steps need: print them now.
				label, _ := provider(one.host)
				if label == "" {
					label = one.engine
				}
				fmt.Fprintf(io.Out, "Found one database, which the apps on this server use: %s %s, database %s.\n(If that is not the database to watch: sudo kiyesi databases setup <engine> <database> --host <host>)\n\n", label, one.host, one.db)
				engine, db, host = one.engine, one.db, one.host
			} else {
				engine = strings.ToLower(args[0])
				db = "app"
				if len(args) == 2 {
					db = args[1]
				}
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
			login = strings.ToLower(login)
			if !validLogin(login) {
				return usageErr("%q is not a way Kiyesi signs in: password, aws-iam, gcp-iam, azure-identity, certificate, aws-secret or vault", login)
			}
			if vaultAuth != "" && vaultAuth != "aws" && vaultAuth != "gcp" && vaultAuth != "azure" && vaultAuth != "approle" {
				return usageErr("--vault-auth is aws, gcp, azure or approle")
			}
			if vaultAddr != "" && !strings.HasPrefix(vaultAddr, "https://") {
				return usageErr("--vault is Vault's https:// address")
			}
			s := setupFor{out: io.Out, db: db, host: host, port: port, container: container, systemd: systemdVersion(),
				vaultAddr: vaultAddr, vaultAuth: vaultAuth}
			if container != "" && !s.reachContainer(engineDefaultPort(engine)) {
				return nil
			}
			if login == "" {
				login = s.bestLogin(engine)
			}
			s.login = login
			if done, err := s.cloud(engine); done || err != nil {
				return err
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
	cmd.Flags().StringVar(&login, "login", "", "how Kiyesi signs in: password, aws-iam, gcp-iam, azure-identity, certificate, aws-secret or vault (the safest one for the host when not given)")
	cmd.Flags().StringVar(&vaultAddr, "vault", "", "with --login vault: your Vault's https:// address")
	cmd.Flags().StringVar(&vaultAuth, "vault-auth", "", "with --login vault: how this server signs in to Vault: aws, gcp, azure or approle")
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
		return "AWS RDS", "The admin is the database's master user."
	case strings.HasSuffix(h, ".supabase.co") || strings.HasSuffix(h, ".supabase.com"):
		return "Supabase", "The admin is postgres, with the database password from Supabase: Project Settings, Database."
	case strings.HasSuffix(h, ".neon.tech"):
		return "Neon", "The admin is the role in Neon's connection string (Neon: Connect)."
	case strings.HasSuffix(h, ".ondigitalocean.com"):
		return "DigitalOcean", "The admin is doadmin; this server must be in the database's trusted sources."
	case strings.HasSuffix(h, ".database.azure.com"):
		return "Azure Database", "The admin is the server's admin user."
	case strings.HasSuffix(h, ".psdb.cloud"):
		return "PlanetScale", "PlanetScale makes passwords in its dashboard, and its smallest role, Reader, can read rows: Kiyesi reads only sizes, but that password could read data."
	case strings.HasSuffix(h, ".upstash.io"):
		return "Upstash", "If Upstash refuses ACL SETUSER, it has no way to make a user that only reads INFO."
	}
	return "", ""
}

// foundDatabases is every database setup finds for this server.
type foundDatabases struct {
	// local are the engines installed on this server, as setup's names.
	local [][2]string // label, engine
	// containers are the database containers: name and engine.
	containers [][2]string
	// used are the hosted databases the apps' settings name.
	used      []usedDatabase
	dockerErr error
}

func findDatabases() foundDatabases {
	var f foundDatabases
	for _, d := range postgresSockets {
		if fileThere(d + "/.s.PGSQL.5432") {
			f.local = append(f.local, [2]string{"PostgreSQL", "postgres"})
			break
		}
	}
	for _, sock := range mysqlSockets {
		if fileThere(sock) {
			if fileThere("/usr/sbin/mariadbd") {
				f.local = append(f.local, [2]string{"MariaDB", "mariadb"})
			} else {
				f.local = append(f.local, [2]string{"MySQL", "mysql"})
			}
			break
		}
	}
	if fileThere("/usr/bin/mongod") || fileThere("/var/run/mongodb") {
		f.local = append(f.local, [2]string{"MongoDB", "mongodb"})
	}
	if fileThere("/usr/bin/redis-server") || fileThere("/usr/bin/valkey-server") {
		f.local = append(f.local, [2]string{"Redis", "redis"})
	}
	containers, err := dockerContainers()
	f.dockerErr = err
	var used []usedDatabase
	for _, c := range containers {
		if !containerNamePattern.MatchString(c[0]) {
			continue
		}
		if e := imageEngine(c[1]); e != "" {
			f.containers = append(f.containers, [2]string{c[0], e})
			continue
		}
		used = append(used, databasesIn(dockerEnv(c[0]))...)
	}
	for _, file := range appEnvFiles() {
		b, err := os.ReadFile(file) // #nosec G304 -- an app's settings file under /opt, /srv or /var/www, read for host names only
		if err == nil {
			used = append(used, databasesIn(strings.Split(string(b), "\n"))...)
		}
	}
	seen := map[string]bool{}
	for _, u := range used {
		key := u.engine + " " + u.host + " " + u.db
		if !seen[key] {
			seen[key] = true
			f.used = append(f.used, u)
		}
	}
	return f
}

// only is the one database found, when there is exactly one and setup knows
// all it needs to print its steps: a hosted one an app names, with its
// database.
func (f foundDatabases) only() *usedDatabase {
	if len(f.local) == 0 && len(f.containers) == 0 && len(f.used) == 1 && f.used[0].db != "<database>" {
		return &f.used[0]
	}
	return nil
}

// listDatabases names every database found for this server, and how to set
// up one it cannot find.
func listDatabases(out io.Writer, f foundDatabases) {
	fmt.Fprintln(out, "On this server:")
	for _, l := range f.local {
		fmt.Fprintf(out, "  %-12s sudo kiyesi databases setup %s <database>\n", l[0], l[1])
	}
	if len(f.local) == 0 {
		fmt.Fprintln(out, "  none installed here")
	}
	if f.dockerErr != nil {
		fmt.Fprintf(out, "\nDocker is installed here, but asking it for its containers failed: %v\nRun this as root, and check the Docker service is running (systemctl status docker).\n", f.dockerErr)
	}
	if len(f.containers) > 0 {
		fmt.Fprintln(out, "\nIn Docker containers on this server:")
		for _, c := range f.containers {
			fmt.Fprintf(out, "  %-24s sudo kiyesi databases setup %s <database> --container %s\n", c[0], c[1], c[0])
		}
	}
	if len(f.used) > 0 {
		fmt.Fprintln(out, "\nUsed by the apps on this server (from their settings: host only, never a password):")
		for _, u := range f.used {
			label, _ := provider(u.host)
			if label == "" {
				label = u.host
			} else {
				label += " " + u.host
			}
			fmt.Fprintf(out, "  %s\n    sudo kiyesi databases setup %s %s --host %s\n", label, u.engine, u.db, u.host)
		}
	}
	if len(f.local)+len(f.containers)+len(f.used) == 0 {
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
	// login is how Kiyesi will sign in (password, aws-iam, …), and the
	// Vault's address and sign-in when it is vault.
	login     string
	vaultAddr string
	vaultAuth string
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

// config adds the database to Kiyesi's settings, with the password
// setting that names where its password is kept ("" for none).
func (s *setupFor) config(url, password string) {
	entry := "  - name: " + s.db + "\n    url: " + url
	if password != "" {
		entry += "\n    password: " + password
	}
	settings, _ := os.ReadFile(setupSettingsPath) // #nosec G304 -- Kiyesi's own settings file
	var was *config.Database
	if c, err := config.Load(setupSettingsPath); err == nil {
		for i := range c.Databases {
			if c.Databases[i].Name == s.db {
				was = &c.Databases[i]
			}
		}
	}
	switch where := databasesSection(string(settings), s.db); where {
	case "listed":
		if was != nil && was.URL == url && was.Password == password {
			s.say("It is already in " + setupSettingsPath + " as " + s.db + ", set this way.")
			break
		}
		s.say("It is in "+setupSettingsPath+" as "+s.db+", set another way. Open the file (sudo nano "+setupSettingsPath+") and make its entry read exactly as below, its other lines (limit, backups) kept; the address holds no password:", entry)
	case "last", "none":
		lines := strings.Split(entry, "\n")
		if where == "none" {
			lines = append([]string{"databases:"}, lines...)
		}
		s.say("Add it to Kiyesi's settings, "+setupSettingsPath+" (the address holds no password):",
			printfLines(lines...)+" | sudo tee -a "+setupSettingsPath+" >/dev/null")
		if strings.Contains(entry, "<") {
			fmt.Fprintln(s.out, "   Put the value each <…> names in its place before running it.")
		}
	default:
		s.say("Add it under databases: in "+setupSettingsPath+" (the address holds no password):", entry)
	}
	s.say("Check it: Kiyesi signs in the way the agent will, and says how, and any right its user should not have.",
		"sudo kiyesi databases check")
	// Moving away from a password kept here: once the check shows the new
	// way, the old password goes, so nothing is left to steal.
	if was != nil && was.Password == "credential" && password != "credential" {
		what := "When the check says it signs in the new way, remove the old password from this server:"
		if strings.HasSuffix(strings.ToLower(s.host), ".mongodb.net") {
			what = "When the check says it signs in the new way, in Atlas's Database Users tab delete the kiyesi_ro user whose method is Password (keep the Certificate or AWS IAM one), and remove its password from this server:"
		}
		s.say(what, "sudo rm -f "+dbwatch.CredstoreDir+"/"+dbwatch.CredentialPrefix+s.db+" "+dbwatch.OwnCredentialsDir+"/"+s.db+".enc")
	}
	fmt.Fprintln(s.out, "\nThe agent reads it again within 5 minutes. Guide: https://docs.kiyesi.dev/guides/databases/")
}

// caDir keeps the certificate authorities of providers that sign their
// databases' certificates themselves.
const caDir = "/etc/kiyesi/ca"

// caStep adds the step that keeps the provider's own certificate authority
// here, for a provider whose certificates no system trusts by itself, and
// gives its file; "" when the system's authorities check the certificate.
func (s *setupFor) caStep() string {
	name, _ := provider(s.host)
	paste := func(path string) []string {
		return []string{"sudo install -d -m 755 " + caDir, "sudo tee " + path + " >/dev/null"}
	}
	switch name {
	case "AWS RDS":
		path := caDir + "/aws-rds.pem"
		s.say("Fetch AWS's certificate authority for RDS, so the database's certificate is checked against it:",
			"sudo install -d -m 755 "+caDir,
			"sudo curl -fsSL -o "+path+" https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem")
		return path
	case "Supabase":
		path := caDir + "/supabase.pem"
		s.say("Supabase signs its databases' certificates itself. In Supabase: Project Settings, Database, SSL Configuration, Download certificate. Open the file, copy all of it, run this, paste it, then press Ctrl-D:", paste(path)...)
		return path
	case "DigitalOcean":
		path := caDir + "/digitalocean.pem"
		s.say("DigitalOcean signs its databases' certificates itself. On the database's Overview page, Connection Details, Download CA certificate (or: doctl databases get-ca <cluster> --format Certificate --no-header). Copy all of it, run this, paste it, then press Ctrl-D:", paste(path)...)
		return path
	}
	return ""
}

// supabasePooler is the host and users to reach a Supabase database through
// its session pooler, on a server with no IPv6: the direct connection is
// IPv6 only. The pooler's host is in Supabase's Connect panel.
func supabasePooler(host string) (pooler, ref string, ok bool) {
	h := strings.ToLower(host)
	if !strings.HasPrefix(h, "db.") || !strings.HasSuffix(h, ".supabase.co") || hasIPv6() {
		return "", "", false
	}
	ref = strings.TrimSuffix(strings.TrimPrefix(h, "db."), ".supabase.co")
	return "<the Session pooler host, from Supabase: Connect>", ref, true
}

// databasesSection says where a new database goes in the settings: "none"
// when there is no databases: list, "last" when the list ends the file (so
// an entry can be added at its end), "listed" when this name is there
// already, and "inside" when other settings follow the list.
func databasesSection(settings, name string) string {
	lines := strings.Split(settings, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimRight(l, " \t\r") == "databases:" {
			start = i
			break
		}
	}
	if start < 0 {
		return "none"
	}
	for _, l := range lines[start+1:] {
		t := strings.TrimSpace(l)
		if t == "- name: "+name {
			return "listed"
		}
		if l != "" && l[0] != ' ' && l[0] != '\t' && l[0] != '#' && l[0] != '-' {
			return "inside"
		}
	}
	return "last"
}

// printfLines is one shell command that prints these lines, each in single
// quotes: safe to copy with any indentation, unlike a <<'END' block, whose
// closing line must start the line. The lines hold no single quote.
// shellDQ escapes text for inside double quotes in the shell: what the
// shell would read there (\\, ", backquotes, $) is passed as written.
func shellDQ(text string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`).Replace(text)
}

func printfLines(lines ...string) string {
	q := make([]string, len(lines))
	for i, l := range lines {
		q[i] = "'" + l + "'"
	}
	return `printf '%s\n' ` + strings.Join(q, " ")
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
			"sudo -u postgres psql -v ON_ERROR_STOP=1 -c 'CREATE ROLE "+pgRole+"' -c '"+strings.Join(strings.Split(readOnly, "\n"), "' -c '")+"'")
		s.say("Let this server's root user, which runs the agent, sign in as kiyesi_ro through the socket only (peer). The line goes first in pg_hba.conf, which is read top to bottom:",
			`hba="$(sudo -u postgres psql -tAc 'SHOW hba_file')"; ident="$(sudo -u postgres psql -tAc 'SHOW ident_file')"`,
			`echo 'kiyesi  root  kiyesi_ro' | sudo tee -a "$ident" >/dev/null`,
			`sudo sed -i '1i local  `+s.db+`  kiyesi_ro  peer map=kiyesi' "$hba"`,
			`sudo -u postgres psql -c 'SELECT pg_reload_conf()'`)
		s.config("postgres://kiyesi_ro@/"+s.db+"?host="+socket, "")
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
	pgHost, pgAdmin, pgUser := s.host, "<admin>", "kiyesi_ro"
	if pooler, ref, ok := supabasePooler(s.host); ok {
		fmt.Fprintln(s.out, "Supabase's direct connection is IPv6 only, and this server has no IPv6 address: both steps go through Supabase's Session pooler, port 5432. Put its host, from Supabase: Connect, Session pooler, in place of "+pooler+".")
		pgHost, pgAdmin, pgUser = pooler, "postgres."+ref, "kiyesi_ro."+ref
	}
	var ca string
	if s.host != "" {
		ca = s.caStep()
		root := ""
		if ca != "" {
			root = " sslrootcert=" + ca
		}
		admin = `psql -v ON_ERROR_STOP=1 "host=` + pgHost + ` port=` + strings.Split(s.hostPort(5432), ":")[1] + ` dbname=` + s.db + ` user=` + pgAdmin + ` sslmode=verify-full` + root + `"`
	}
	s.say("Make Kiyesi's user with a random password nobody sees. It may connect and read sizes and counts, never a row, and every session is read-only. Run it as the database's admin:",
		randomPassword,
		`printf "CREATE ROLE `+pgRole+` PASSWORD '%s';\n`+sqlLines(readOnly)+`" "$pw" | `+admin)
	s.keep()
	addr := "127.0.0.1:5432"
	if s.host != "" {
		addr = s.hostPort(5432)
	}
	if s.addr != "" {
		addr = s.addr
	}
	if s.host != "" && pgHost != s.host {
		addr = pgHost + ":5432"
	}
	url := "postgres://" + pgUser + "@" + addr + "/" + s.db
	if s.host != "" {
		url += "?sslmode=verify-full"
		if ca != "" {
			url += "&sslrootcert=" + ca
		}
	}
	s.config(url, s.passwordSetting())
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
			"sudo mysql -e \""+shellDQ("CREATE USER 'kiyesi_ro'@'localhost' IDENTIFIED WITH auth_socket AS 'root' WITH MAX_USER_CONNECTIONS 3; "+fmt.Sprintf(grant, "localhost"))+"\"")
		fmt.Fprintln(s.out, "   If it says the auth_socket plugin is not loaded: sudo mysql -e \"INSTALL PLUGIN auth_socket SONAME 'auth_socket.so'\"")
		s.config("mysql://kiyesi_ro@localhost/"+s.db+"?socket="+socket, "")
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
	var ca string
	if s.host != "" {
		ca = s.caStep()
		tlsOpt := " --ssl-mode=VERIFY_IDENTITY"
		if maria {
			tlsOpt = " --ssl --ssl-verify-server-cert"
		}
		if ca != "" {
			tlsOpt += " --ssl-ca=" + ca
		}
		admin = cli + " -h " + s.host + " -P " + strings.Split(s.hostPort(3306), ":")[1] + " -u <admin> -p" + tlsOpt
	}
	s.say("Make Kiyesi's user with a random password nobody sees, allowed only from "+from+". SHOW VIEW on the one database lets it see its tables' sizes, never their rows. Run it as the database's admin:",
		randomPassword,
		`printf "CREATE USER 'kiyesi_ro'@'`+from+`' IDENTIFIED BY '%s' WITH MAX_USER_CONNECTIONS 3;\n`+sqlLines(fmt.Sprintf(grant, from))+`" "$pw" | `+admin)
	s.keep()
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
		if ca != "" {
			url += "&ca=" + ca
		}
	}
	s.config(url, s.passwordSetting())
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

// mongoRun runs the script as the admin. In a container the admin's
// password comes from the container's settings, so the script can come in
// on standard input; elsewhere mongosh asks for the password there, so the
// script goes in --eval, as one line.
func mongoRun(admin, js string, piped bool) string {
	if piped {
		return printfLines(strings.Split(js, "\n")...) + " | " + admin
	}
	return admin + " --eval '" + strings.Join(strings.Fields(js), " ") + "'"
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
	var ca string
	if s.host != "" {
		ca = s.caStep()
		caOpt := ""
		if ca != "" {
			caOpt = "&tlsCAFile=" + ca
		}
		admin = `KIYESI_PW="$pw" mongosh --quiet "mongodb://` + s.hostPort(27017) + `/admin?tls=true` + caOpt + `" -u <admin>`
	}
	if s.container != "" {
		admin = `sudo docker exec -i -e KIYESI_PW="$pw" ` + s.container + ` sh -c 'exec mongosh --quiet admin -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD"'`
	}
	s.say("Make a role that may only read the database's size and the server's status, and Kiyesi's user with it and a random password nobody sees. Run it as the database's admin:",
		randomPassword,
		mongoRun(admin, s.mongoUserJS(), s.container != ""))
	s.keep()
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
		if ca != "" {
			url += "&tlsCAFile=" + ca
		}
	}
	s.config(url, s.passwordSetting())
}

// atlas is MongoDB Atlas: its roles and users are made in Atlas's website,
// which undoes one made any other way. Every plan allows a custom role.
func (s *setupFor) atlas() {
	cluster := strings.Split(strings.ToLower(s.host), ".")[0]
	s.intro("the MongoDB Atlas database " + s.db + " on " + s.host + ", read-only, with a password kept encrypted")
	fmt.Fprintln(s.out, "Steps 1 and 2 are in Atlas's website: Atlas undoes a user made any other way. The rest are on this server.")
	s.atlasRole()
	s.say("On the Database Users tab, Add New Database User:",
		"Authentication Method:  Password",
		"Username:               kiyesi_ro",
		"Password:               Autogenerate Secure Password, then Copy",
		"Privileges:             under Custom Roles, only kiyesiStats",
		"Restrict Access to Specific Clusters: on, with only "+cluster,
		"Then Add User. Keep the password on your clipboard for the next step.")
	s.say(strings.Replace(s.storeWords(), ":", ". Run this here and paste the password when asked; it is not shown or kept in your history:", 1), s.storeTyped())
	ip := publicIPv4()
	where := "this server's public address (curl -4s https://checkip.amazonaws.com shows it)"
	if ip != "" {
		where = "this server's public address, " + ip + ","
	}
	s.say("In Atlas, on the IP Access List tab, " + where + " must be listed; if it is not, Add IP Address with it alone, then Confirm. When an app on this server already uses this cluster, it is there already.")
	s.config("mongodb+srv://kiyesi_ro@"+s.host+"/"+s.db, "credential")
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
	var ca string
	if s.host != "" {
		ca = s.caStep()
		caOpt := ""
		if ca != "" {
			caOpt = " --cacert " + ca
		}
		admin = "redis-cli --tls" + caOpt + " -h " + s.host + " -p " + strings.Split(s.hostPort(6379), ":")[1] + " -a <the admin password> --no-auth-warning"
	}
	if s.container != "" {
		admin = `sudo docker exec -i ` + s.container + ` sh -c 'exec "$(command -v redis-cli || command -v valkey-cli)" ${REDIS_PASSWORD:+-a "$REDIS_PASSWORD" --no-auth-warning}'`
	}
	s.say("Make Kiyesi's user with a random password nobody sees. It may run only INFO and PING: no key, no value, no setting:",
		randomPassword,
		`printf 'ACL SETUSER kiyesi_ro on >%s -@all +info +ping\n' "$pw" | `+admin)
	s.keep()
	addr := "127.0.0.1:6379"
	if s.host != "" {
		addr = s.hostPort(6379)
	}
	if s.addr != "" {
		addr = s.addr
	}
	scheme, query := "redis", ""
	if s.host != "" {
		scheme = "rediss"
		if ca != "" {
			query = "?ca=" + ca
		}
	}
	s.config(scheme+"://kiyesi_ro@"+addr+query, s.passwordSetting())
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
