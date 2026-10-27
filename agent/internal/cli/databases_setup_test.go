package cli

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/cloudlogin"
)

// The SQL in the printed steps reaches the database as written: the shell
// runs nothing from a name in backquotes or with a dollar in it.
func TestSetupSQLPassesThroughTheShell(t *testing.T) {
	sql := "CREATE USER 'kiyesi_ro'@'127.0.0.1' IDENTIFIED BY '%s';\nGRANT SHOW VIEW ON `sh$op`.* TO 'kiyesi_ro'@'127.0.0.1';"
	line := `printf "` + sqlLines(sql) + `" "pw"`
	out, err := exec.Command("sh", "-c", line).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := strings.Replace(sql, "%s", "pw", 1) + "\n"
	if string(out) != want {
		t.Errorf("the shell passed\n%s\nwant\n%s", out, want)
	}
}

// fakeServer stands in for what setup reads on a server: no database
// installed, these containers, their settings, and these .env files.
func fakeServer(t *testing.T, containers [][2]string, env map[string][]string, envFiles map[string]string, published map[string]string) {
	t.Helper()
	oldC, oldE, oldF, oldP, oldG, oldT, oldS := dockerContainers, dockerEnv, appEnvFiles, dockerPublished, dockerGateway, fileThere, systemdVersion
	oldSettings, oldIP, oldV6, oldAWS := setupSettingsPath, publicIPv4, hasIPv6, thisAWS
	t.Cleanup(func() {
		dockerContainers, dockerEnv, appEnvFiles, dockerPublished, dockerGateway, fileThere, systemdVersion = oldC, oldE, oldF, oldP, oldG, oldT, oldS
		setupSettingsPath, publicIPv4, hasIPv6, thisAWS = oldSettings, oldIP, oldV6, oldAWS
	})
	// Off AWS, unless a test says otherwise.
	thisAWS = func() cloudlogin.AWSInstance { return cloudlogin.AWSInstance{} }
	hasIPv6 = func() bool { return false }
	setupSettingsPath = t.TempDir() + "/config.yaml"
	publicIPv4 = func() string { return "203.0.113.24" }
	dockerContainers = func() ([][2]string, error) { return containers, nil }
	dockerEnv = func(name string) []string { return env[name] }
	dir := t.TempDir()
	var files []string
	for name, body := range envFiles {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	appEnvFiles = func() []string { return files }
	dockerPublished = func(name string, port int) string { return published[name] }
	dockerGateway = func(string) string { return "172.18.0.1" }
	fileThere = func(string) bool { return false }
	systemdVersion = func() int { return 255 }
}

func TestSetupListsWhatTheServerUses(t *testing.T) {
	fakeServer(t,
		[][2]string{{"appstack-api-1", "shop/app-api:latest"}, {"appstack-caddy-1", "caddy:2"}, {"shop-db-1", "postgres:16-alpine"}},
		map[string][]string{"appstack-api-1": {"PATH=/usr/bin", "MONGODB_URI=mongodb+srv://app:" + "s3cret-pw@cluster0.abcde.mongodb.net/shop?retryWrites=true", "PORT=3000"}},
		map[string]string{".env": "DATABASE_URL=postgres://admin:hunter2@orders.c9x.eu-west-1.rds.amazonaws.com:5432/orders\n"},
		nil)
	code, out, _ := runCLI(t, "databases", "setup")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{
		"none installed here",
		"sudo kiyesi databases setup postgres <database> --container shop-db-1",
		"MongoDB Atlas cluster0.abcde.mongodb.net",
		"sudo kiyesi databases setup mongodb shop --host cluster0.abcde.mongodb.net",
		"AWS RDS orders.c9x.eu-west-1.rds.amazonaws.com",
		"sudo kiyesi databases setup postgres orders --host orders.c9x.eu-west-1.rds.amazonaws.com",
		"MongoDB Atlas:            sudo kiyesi databases setup mongodb <database> --host <cluster>.mongodb.net",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, secret := range []string{"s3cret-pw", "hunter2", "app:", "admin:"} {
		if strings.Contains(out, secret) {
			t.Errorf("printed %q from an app's settings:\n%s", secret, out)
		}
	}
}

func TestSetupNothingFoundStillSaysEveryWay(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup")
	for _, want := range []string{"No database was found", "--container <name>", "<cluster>.mongodb.net", "--host <host>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Atlas with a password, when asked for: --login password.
func TestSetupAtlas(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup", "mongodb", "shop", "--host", "cluster0.abcde.mongodb.net", "--login", "password")
	for _, want := range []string{
		"Steps 1 and 2 are in Atlas's website",
		"Security, Database & Network Access, and the Custom Roles tab",
		"dbStats, on the database shop",
		"atlas customDbRoles create kiyesiStats --privilege DB_STATS@shop,SERVER_STATUS",
		"Autogenerate Secure Password, then Copy",
		"under Custom Roles, only kiyesiStats",
		"with only cluster0",
		"IP Access List tab, this server's public address, 203.0.113.24,",
		`sudo sh -c 'systemd-ask-password "Password for kiyesi_ro (not shown):" | systemd-creds encrypt - /etc/credstore.encrypted/kiyesi.db.shop'`,
		"printf '%s\\n' 'databases:' '  - name: shop' '    url: mongodb+srv://kiyesi_ro@cluster0.abcde.mongodb.net/shop' '    password: credential' | sudo tee -a " + setupSettingsPath + " >/dev/null",
		"password: credential",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Never mongosh for Atlas: Atlas undoes roles made there.
	if strings.Contains(out, "createRole") {
		t.Errorf("mongosh steps for Atlas:\n%s", out)
	}
}

func TestSetupInAContainer(t *testing.T) {
	fakeServer(t, nil, nil, nil, map[string]string{"shop-db-1": "0.0.0.0:15432", "quiet-db-1": ""})
	_, out, _ := runCLI(t, "databases", "setup", "postgres", "orders", "--container", "shop-db-1")
	for _, want := range []string{
		`sudo docker exec -i shop-db-1 sh -c 'exec psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}"'`,
		"published on every address of this server",
		`ports: ["127.0.0.1:15432:5432"]`,
		"url: postgres://kiyesi_ro@127.0.0.1:15432/orders",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	_, out, _ = runCLI(t, "databases", "setup", "mysql", "shop", "--container", "quiet-db-1")
	if !strings.Contains(out, `"127.0.0.1:3306:3306"`) || strings.Contains(out, "CREATE USER") {
		t.Errorf("an unpublished container:\n%s", out)
	}
}

// Docker installed but not answering is said, not taken for no containers.
func TestSetupSaysWhenDockerCannotBeAsked(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	dockerContainers = func() ([][2]string, error) {
		return nil, errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")
	}
	_, out, _ := runCLI(t, "databases", "setup")
	if !strings.Contains(out, "Docker is installed here, but asking it for its containers failed: Cannot connect to the Docker daemon") {
		t.Errorf("%s", out)
	}
}

// The owner's server: no database of its own, one app using Atlas. setup
// alone prints that database's steps, with no second command to copy.
func TestSetupPrintsTheOnlyDatabaseStraightAway(t *testing.T) {
	fakeServer(t,
		[][2]string{{"appstack-api-1", "shop/app-api:latest"}, {"appstack-caddy-1", "caddy:2"}},
		map[string][]string{"appstack-api-1": {"MONGODB_URI=mongodb+srv://app:" + "s3cret@cluster0.ab1cd.mongodb.net/test?retryWrites=true"}},
		nil, nil)
	_, out, _ := runCLI(t, "databases", "setup")
	for _, want := range []string{
		"Found one database, which the apps on this server use: MongoDB Atlas cluster0.ab1cd.mongodb.net, database test.",
		"Steps to watch the MongoDB Atlas database test on cluster0.ab1cd.mongodb.net",
		"with only cluster0",
		"sudo install -m 600 /dev/null /etc/kiyesi/credentials/test.pem",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3cret") || strings.Contains(out, "app:") {
		t.Errorf("printed the app's password:\n%s", out)
	}
}

// The settings step is one command that is right for the file as it is.
func TestSetupAddsToTheSettingsAsTheyAre(t *testing.T) {
	for name, c := range map[string]struct{ settings, want, not string }{
		"no file":        {"", "'databases:' '  - name: test'", ""},
		"no databases":   {"token: x\n", "'databases:' '  - name: test'", ""},
		"databases last": {"token: x\ndatabases:\n  - name: orders\n    url: postgres://kiyesi_ro@/orders?host=/run/postgresql\n", "printf '%s\\n' '  - name: test'", "'databases:'"},
		"listed":         {"databases:\n  - name: test\n    url: x\n", "It is already in", "sudo tee -a"},
		"inside":         {"databases:\n  - name: orders\n    url: x\nlogs:\n  level: info\n", "Add it under databases:", "sudo tee -a"},
	} {
		t.Run(name, func(t *testing.T) {
			fakeServer(t, nil, nil, nil, nil)
			if c.settings != "" {
				if err := os.WriteFile(setupSettingsPath, []byte(c.settings), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, out, _ := runCLI(t, "databases", "setup", "mongodb", "test", "--host", "c.abcde.mongodb.net")
			if !strings.Contains(out, c.want) || (c.not != "" && strings.Contains(out, c.not)) {
				t.Errorf("want %q, not %q, in:\n%s", c.want, c.not, out)
			}
		})
	}
}

// Every command setup prints is one line, safe to copy with its indentation:
// a <<'END' block hangs when its closing line is copied indented, as a
// person's first try at the settings step did.
func TestSetupCommandsAreSafeToCopy(t *testing.T) {
	fakeServer(t, nil, nil, nil, map[string]string{"db-1": "127.0.0.1:5432"})
	fileThere = func(p string) bool {
		return p == "/var/run/postgresql/.s.PGSQL.5432" || p == "/var/run/mysqld/mysqld.sock"
	}
	for _, args := range [][]string{
		{"postgres", "orders"}, {"mysql", "shop"}, {"mariadb", "shop"}, {"mongodb", "catalogue"}, {"redis", "cache"},
		{"postgres", "orders", "--host", "db.example.com"}, {"mysql", "shop", "--host", "db.example.com"},
		{"mongodb", "catalogue", "--host", "db.example.com"}, {"redis", "cache", "--host", "db.example.com"},
		{"mongodb", "shop", "--host", "c.abcde.mongodb.net"},
		{"postgres", "orders", "--container", "db-1"}, {"mongodb", "catalogue", "--container", "db-1"},
	} {
		_, out, _ := runCLI(t, append([]string{"databases", "setup"}, args...)...)
		if strings.Contains(out, "<<") {
			t.Errorf("%v prints a << block:\n%s", args, out)
		}
	}
}

// Providers that sign their databases' certificates themselves: the steps
// keep their authority, and the address checks the certificate against it.
func TestSetupHostedWithTheirOwnCertificateAuthority(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"postgres", "orders", "--host", "orders.c9x.eu-west-1.rds.amazonaws.com"}, []string{
			"sudo curl -fsSL -o /etc/kiyesi/ca/aws-rds.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
			"sslmode=verify-full sslrootcert=/etc/kiyesi/ca/aws-rds.pem",
			"url: postgres://kiyesi_ro@orders.c9x.eu-west-1.rds.amazonaws.com:5432/orders?sslmode=verify-full&sslrootcert=/etc/kiyesi/ca/aws-rds.pem",
			"The admin is the database's master user.",
		}},
		{[]string{"mysql", "shop", "--host", "shop.c9x.eu-west-1.rds.amazonaws.com"}, []string{
			"--ssl-mode=VERIFY_IDENTITY --ssl-ca=/etc/kiyesi/ca/aws-rds.pem",
			"url: mysql://kiyesi_ro@shop.c9x.eu-west-1.rds.amazonaws.com:3306/shop?tls=true&ca=/etc/kiyesi/ca/aws-rds.pem",
		}},
		{[]string{"postgres", "app", "--host", "db-postgresql-lon1-1.b.db.ondigitalocean.com", "--port", "25060"}, []string{
			"Download CA certificate",
			"sudo tee /etc/kiyesi/ca/digitalocean.pem >/dev/null",
			":25060/app?sslmode=verify-full&sslrootcert=/etc/kiyesi/ca/digitalocean.pem",
		}},
		// No IPv6 on the server: Supabase's Session pooler, with its users.
		{[]string{"postgres", "postgres", "--host", "db.abcdefgh.supabase.co"}, []string{
			"Download certificate",
			"Session pooler",
			"user=postgres.abcdefgh sslmode=verify-full sslrootcert=/etc/kiyesi/ca/supabase.pem",
			"url: postgres://kiyesi_ro.abcdefgh@<the Session pooler host, from Supabase: Connect>:5432/postgres?sslmode=verify-full&sslrootcert=/etc/kiyesi/ca/supabase.pem",
		}},
		// Neon's certificates are signed by an authority every system trusts.
		{[]string{"postgres", "neondb", "--host", "ep-cool-1.eu-central-1.aws.neon.tech"}, []string{
			"url: postgres://kiyesi_ro@ep-cool-1.eu-central-1.aws.neon.tech:5432/neondb?sslmode=verify-full",
		}},
	} {
		_, out, _ := runCLI(t, append([]string{"databases", "setup"}, c.args...)...)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: missing %q in:\n%s", c.args, w, out)
			}
		}
		if c.args[3] == "ep-cool-1.eu-central-1.aws.neon.tech" && strings.Contains(out, "/etc/kiyesi/ca/") {
			t.Errorf("Neon needs no certificate authority of its own:\n%s", out)
		}
	}
}
