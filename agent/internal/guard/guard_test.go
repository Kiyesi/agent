package guard

import (
	"encoding/json"
	"fmt"
	"io/fs"
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

// oldRun writes the record of a guarded run as kiyesi guard made it before
// 0.40.0: every file in root with its sum, secrets noted and not kept.
func oldRun(t *testing.T, store Store, id, root string, at time.Time) *Manifest {
	t.Helper()
	m := &Manifest{ID: id, Command: []string{"./deploy.sh"}, User: "ada", At: at, Root: root}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		info, _ := os.Lstat(p)
		f := File{Path: filepath.ToSlash(rel), Mode: info.Mode(), Kept: !Secret(filepath.ToSlash(rel))}
		if info.Mode()&fs.ModeSymlink != 0 {
			f.Link, _ = os.Readlink(p)
		} else {
			f.Sum, _ = fileSum(p)
		}
		m.Files = append(m.Files, f)
		return nil
	})
	data, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Join(store.Dir, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, id, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

// What changed since a run from before 0.40.0: changed, added and removed
// files, a link pointed elsewhere, and a secret noted though never kept.
func TestChangesSinceAnOldRun(t *testing.T) {
	root := etc(t)
	store := Store{Dir: filepath.Join(t.TempDir(), "guard")}
	m := oldRun(t, store, "e207", root, time.Now())
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
	var got []string
	for _, c := range Changes(m) {
		got = append(got, fmt.Sprintf("%s %s %v", c.Kind, c.Path, c.Kept))
	}
	want := "removed hosts true|changed nginx/enabled true|added nginx/new.conf true|changed nginx/nginx.conf true|changed shadow false"
	if strings.Join(got, "|") != want {
		t.Fatalf("changes:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
}

// Old runs are read back, newest first; an id that is not one is refused.
func TestOldRunsAreRead(t *testing.T) {
	root := etc(t)
	store := Store{Dir: filepath.Join(t.TempDir(), "guard")}
	at := time.Now()
	oldRun(t, store, "aaaa", root, at)
	oldRun(t, store, "bbbb", root, at.Add(time.Minute))
	list, _ := store.List()
	if len(list) != 2 || list[0].ID != "bbbb" {
		t.Fatalf("list %+v", list)
	}
	if _, err := store.Get("../x"); err == nil {
		t.Fatal("a path was taken as an id")
	}
}
