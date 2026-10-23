package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/keys"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type edit struct {
	user, path  string
	remove, add []string
}

// fakeWriter records each change and makes it in the test's folder.
type fakeWriter struct {
	root  string
	edits []edit
}

func (f *fakeWriter) Edit(_ context.Context, a keys.Account, path string, remove, add []string) error {
	f.edits = append(f.edits, edit{a.Name, path, remove, add})
	p := filepath.Join(f.root, path)
	data, _ := os.ReadFile(p)
	return os.WriteFile(p, keys.Edit(data, remove, add), 0o600)
}

func keyLine(t *testing.T, name string) (string, string) {
	t.Helper()
	l, _ := os.ReadFile("../keys/testdata/" + name + ".pub")
	f, _ := os.ReadFile("../keys/testdata/" + name + ".fp")
	return strings.TrimSpace(string(l)), strings.TrimSpace(string(f))
}

// keysServer is a server with root and ada, root holding both test keys
// and ada the RSA one.
func keysServer(t *testing.T) (*fakeWriter, string) {
	t.Helper()
	root := t.TempDir()
	ed, _ := keyLine(t, "ed25519")
	rsa, _ := keyLine(t, "rsa")
	write := func(p, data string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nada:x:1000:1000::/home/ada:/bin/bash\n")
	write("root/.ssh/authorized_keys", ed+"\n"+rsa+"\n")
	write("home/ada/.ssh/authorized_keys", rsa+"\n")
	w := &fakeWriter{root: root}
	oldFS, oldW, oldRoot, oldStore := keysFS, keysWriter, keysAsRoot, keysStore
	t.Cleanup(func() { keysFS, keysWriter, keysAsRoot, keysStore = oldFS, oldW, oldRoot, oldStore })
	keysFS = func() system.RootFS { return system.NewRootFS(root) }
	keysWriter = w
	keysAsRoot = func() bool { return true }
	store := filepath.Join(t.TempDir(), "fixes")
	keysStore = func() *fix.Store { return &fix.Store{Dir: store} }
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KIYESI_ETC", t.TempDir())
	return w, root
}

func TestKeysLists(t *testing.T) {
	keysServer(t)
	_, edFP := keyLine(t, "ed25519")
	code, out, _ := runCLI(t, "keys")
	if code != ExitOK || !strings.Contains(out, "ada@laptop") || !strings.Contains(out, edFP) || !strings.Contains(out, "ACCOUNT") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if strings.Contains(out, "AAAA") {
		t.Errorf("a key itself was printed:\n%s", out)
	}
	code, out, _ = runCLI(t, "keys", "--json")
	var ks []map[string]any
	if err := json.Unmarshal([]byte(out), &ks); err != nil || code != ExitOK || len(ks) != 3 {
		t.Fatalf("code %d, %v: %s", code, err, out)
	}
	if _, has := ks[0]["path"]; has {
		t.Error("the file path is sent; it should stay on the server")
	}
}

func TestKeysRemoveEverywhereAndUndo(t *testing.T) {
	w, root := keysServer(t)
	_, rsaFP := keyLine(t, "rsa")
	code, out, errOut := runCLI(t, "keys", "remove", rsaFP, "--yes")
	if code != ExitOK || !strings.Contains(out, "from root, ada") || !strings.Contains(out, "undo: sudo kiyesi fix undo") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	if len(w.edits) != 2 || w.edits[0].user != "root" || w.edits[1].user != "ada" || len(w.edits[1].remove) != 1 {
		t.Fatalf("edits = %+v", w.edits)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "home/ada/.ssh/authorized_keys")); len(strings.TrimSpace(string(data))) != 0 {
		t.Fatalf("ada's file = %q", data)
	}
	recs, _ := keysStore().List()
	if len(recs) != 1 || recs[0].Fix != "keys" || len(recs[0].Keys) != 2 || !recs[0].CanUndo {
		t.Fatalf("records = %+v", recs)
	}
	// Undo puts each line back with that account's own rights.
	if err := keysStore().Undo(context.Background(), fix.RealHost{}, &recs[0]); err != nil {
		t.Fatal(err)
	}
	if got := w.edits[len(w.edits)-1]; got.user != "ada" || len(got.add) != 1 {
		t.Fatalf("undo edit = %+v", got)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "home/ada/.ssh/authorized_keys")); !strings.Contains(string(data), "ssh-rsa") {
		t.Fatalf("ada's key not back: %q", data)
	}
}

func TestKeysRemoveNeverLocksYouOut(t *testing.T) {
	w, _ := keysServer(t)
	_, rsaFP := keyLine(t, "rsa")
	t.Setenv("SUDO_USER", "ada")
	code, _, errOut := runCLIEnv(t, []string{"SUDO_USER=ada"}, "keys", "remove", rsaFP, "--yes")
	if code != ExitUsage || !strings.Contains(errOut, "only key ada signs in with") || len(w.edits) != 0 {
		t.Fatalf("code %d, err %q, edits %+v", code, errOut, w.edits)
	}
}

func TestKeysRemoveAsksAndChecks(t *testing.T) {
	w, _ := keysServer(t)
	_, edFP := keyLine(t, "ed25519")
	if code, _, errOut := runCLI(t, "keys", "remove", "not-a-key"); code != ExitUsage || !strings.Contains(errOut, "SHA256:") {
		t.Fatalf("code %d, %q", code, errOut)
	}
	if code, _, _ := runCLI(t, "keys", "remove", "SHA256:"+strings.Repeat("A", 43)); code != ExitUsage {
		t.Fatalf("an unknown key: code %d", code)
	}
	if code, _, _ := runCLI(t, "keys", "remove", edFP, "--json"); code != ExitUsage {
		t.Fatalf("--json without --yes: code %d", code)
	}
	// Without --yes and no answer, nothing changes.
	if code, out, _ := runCLI(t, "keys", "remove", edFP); code != ExitOK || !strings.Contains(out, "Nothing changed") || len(w.edits) != 0 {
		t.Fatalf("code %d, out %q, edits %+v", code, out, w.edits)
	}
	keysAsRoot = func() bool { return false }
	if code, _, errOut := runCLI(t, "keys"); code != ExitNoAccess || !strings.Contains(errOut, "sudo kiyesi keys") {
		t.Fatalf("code %d, %q", code, errOut)
	}
}

func TestKeysRemoveKeepsToFixOff(t *testing.T) {
	w, _ := keysServer(t)
	_, edFP := keyLine(t, "ed25519")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("fix: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "keys", "remove", edFP, "--yes", "--config", cfg)
	if code != ExitNoAccess || !strings.Contains(errOut, "fix: off") || len(w.edits) != 0 {
		t.Fatalf("code %d %q, edits %+v", code, errOut, w.edits)
	}
}
