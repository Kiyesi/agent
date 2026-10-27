package cli

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
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
	t.Cleanup(func() {
		dockerContainers, dockerEnv, appEnvFiles, dockerPublished, dockerGateway, fileThere, systemdVersion = oldC, oldE, oldF, oldP, oldG, oldT, oldS
	})
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

func TestSetupAtlas(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup", "mongodb", "shop", "--host", "cluster0.abcde.mongodb.net")
	for _, want := range []string{
		"atlas customDbRoles create kiyesiStats --privilege DB_STATS@shop,SERVER_STATUS",
		"Autogenerate Secure Password",
		"only the custom role kiyesiStats",
		"Network Access",
		`sudo sh -c 'systemd-ask-password "Password for kiyesi_ro (not shown):" | systemd-creds encrypt - /etc/credstore.encrypted/kiyesi.db.shop'`,
		"url: mongodb+srv://kiyesi_ro@cluster0.abcde.mongodb.net/shop",
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
