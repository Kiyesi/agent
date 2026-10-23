package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretsAreNeverCopied(t *testing.T) {
	for _, p := range []string{"shadow", "gshadow-", "ssl/private/site.key", "letsencrypt/live/x/privkey.pem", "ssh/ssh_host_ed25519_key", "nginx/certs/shop.key", "kiyesi/agent.yaml"} {
		if !Secret(p) {
			t.Errorf("%s should never be copied", p)
		}
	}
	for _, p := range []string{"passwd", "group", "ssh/ssh_host_ed25519_key.pub", "ssh/sshd_config", "nginx/nginx.conf", "sudoers"} {
		if Secret(p) {
			t.Errorf("%s is a settings file and should be copied", p)
		}
	}
}

// etc is a small /etc in a temporary folder.
func etc(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "etc")
	files := map[string]string{
		"nginx/nginx.conf":     "worker_processes auto;\n",
		"nginx/sites/shop":     "server { listen 80; }\n",
		"hosts":                "127.0.0.1 localhost\n",
		"shadow":               "root:$6$secret:19000::::::\n",
		"ssl/private/shop.key": "-----BEGIN PRIVATE KEY-----\n",
	}
	for p, data := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("sites/shop", filepath.Join(root, "nginx/enabled")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestSnapshotChangesAndRestore(t *testing.T) {
	root := etc(t)
	store := Store{Dir: filepath.Join(t.TempDir(), "guard")}
	m, err := store.Snapshot(root, []string{"./deploy.sh"}, "ada", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, f := range m.Files {
		kept[f.Path] = f.Kept
	}
	if !kept["nginx/nginx.conf"] || !kept["nginx/enabled"] || kept["shadow"] || kept["ssl/private/shop.key"] {
		t.Fatalf("kept = %v", kept)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, m.ID, "files", "shadow")); err == nil {
		t.Fatal("a password file was copied")
	}
	if info, _ := os.Stat(store.Dir); info.Mode().Perm() != 0o700 {
		t.Errorf("the guard folder is %v, want 0700", info.Mode().Perm())
	}

	// The command breaks nginx, removes hosts, adds a file, changes the
	// password file and points the link elsewhere.
	write := func(p, data string) {
		if err := os.WriteFile(filepath.Join(root, p), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("nginx/nginx.conf", "worker_processes auto\n")
	write("nginx/new.conf", "include broken;\n")
	write("shadow", "root:$6$changed:19000::::::\n")
	if err := os.Remove(filepath.Join(root, "hosts")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "nginx/enabled")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/elsewhere", filepath.Join(root, "nginx/enabled")); err != nil {
		t.Fatal(err)
	}
	changes := Changes(m)
	var got []string
	for _, c := range changes {
		got = append(got, c.Kind+" "+c.Path)
	}
	want := "removed hosts|changed nginx/enabled|added nginx/new.conf|changed nginx/nginx.conf|changed shadow"
	if strings.Join(got, "|") != want {
		t.Fatalf("changes:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}

	restored, left, err := store.Restore(m, changes)
	if err != nil {
		t.Fatal(err)
	}
	if restored != 4 || len(left) != 1 || left[0] != "shadow" {
		t.Fatalf("restored %d, left %v", restored, left)
	}
	read := func(p string) string {
		b, _ := os.ReadFile(filepath.Join(root, p))
		return string(b)
	}
	if read("nginx/nginx.conf") != "worker_processes auto;\n" || read("hosts") != "127.0.0.1 localhost\n" {
		t.Fatal("files not put back")
	}
	if _, err := os.Lstat(filepath.Join(root, "nginx/new.conf")); err == nil {
		t.Fatal("the added file is still there")
	}
	if l, _ := os.Readlink(filepath.Join(root, "nginx/enabled")); l != "sites/shop" {
		t.Fatalf("link = %q", l)
	}
	if read("shadow") != "root:$6$changed:19000::::::\n" {
		t.Fatal("the password file was touched")
	}
	if left := Changes(m); len(left) != 1 || left[0].Path != "shadow" {
		t.Fatalf("after restore: %+v", left)
	}
}

func TestStoreKeepsTheLastFive(t *testing.T) {
	root := etc(t)
	store := Store{Dir: filepath.Join(t.TempDir(), "guard")}
	at := time.Now()
	var ids []string
	for i := range 7 {
		m, err := store.Snapshot(root, []string{"true"}, "ada", at.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	store.Prune()
	list, _ := store.List()
	if len(list) != Keep || list[0].ID != ids[6] {
		t.Fatalf("kept %d, newest %s", len(list), list[0].ID)
	}
	if _, err := store.Get(ids[0]); err == nil {
		t.Fatal("the oldest is still there")
	}
	if _, err := store.Get("../x"); err == nil {
		t.Fatal("a path was taken as an id")
	}
}

func TestWorse(t *testing.T) {
	before := State{Letter: "A", Score: 95, Failed: []string{"old.service"}, Containers: []string{"api", "db"},
		Sites: map[string]int{"http://127.0.0.1/": 200, "https://127.0.0.1/": 301, "http://127.0.0.1:9/": 0}}
	after := State{Letter: "B", Score: 80, Failed: []string{"nginx.service", "old.service"}, Containers: []string{"db"},
		Sites: map[string]int{"http://127.0.0.1/": 502, "https://127.0.0.1/": 0, "http://127.0.0.1:9/": 0}}
	got := strings.Join(Worse(before, after), "|")
	want := "nginx.service failed|container api stopped|http://127.0.0.1/ answers 502 (before: 200)|https://127.0.0.1/ does not answer (before: 301)|the grade fell from A 95 to B 80"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if w := Worse(before, before); len(w) != 0 {
		t.Fatalf("nothing changed, got %v", w)
	}
}

func TestPackagesAndBackCommands(t *testing.T) {
	ch := PackageChanges([]string{"nginx 1.24.0-1", "openssl 3.0.2-1", "old 1.0"}, []string{"nginx 1.24.0-2", "openssl 3.0.2-1", "new 2.0"})
	var got []string
	for _, c := range ch {
		got = append(got, c.Name+":"+BackCommand(c))
	}
	want := "new:sudo apt-get remove new|nginx:sudo apt-get install --allow-downgrades nginx=1.24.0-1|old:sudo apt-get install old=1.0"
	if strings.Join(got, "|") != want {
		t.Fatalf("got %s", strings.Join(got, "|"))
	}
}

func TestOnlyThisServersSitesAreAsked(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:3000/health", "https://localhost/", "http://[::1]:8080/"} {
		if err := LocalSite(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com/", "http://10.0.0.5/", "ftp://127.0.0.1/", "127.0.0.1"} {
		if LocalSite(bad) == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if got := DefaultSites([]int{22, 443, 80}); strings.Join(got, " ") != "https://127.0.0.1/ http://127.0.0.1/" {
		t.Errorf("default sites = %v", got)
	}
	if got := ParseFailed("nginx.service loaded failed failed A high performance web server\nbackup.timer loaded failed failed x\n"); strings.Join(got, ",") != "nginx.service,backup.timer" {
		t.Errorf("failed = %v", got)
	}
}
