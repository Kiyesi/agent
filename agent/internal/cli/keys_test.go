package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func keyLine(t *testing.T, name string) (string, string) {
	t.Helper()
	l, _ := os.ReadFile("../keys/testdata/" + name + ".pub")
	f, _ := os.ReadFile("../keys/testdata/" + name + ".fp")
	return strings.TrimSpace(string(l)), strings.TrimSpace(string(f))
}

// keysServer is a server with root and ada, root holding both test keys
// and ada the RSA one.
func keysServer(t *testing.T) string {
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
	oldFS, oldRoot := keysFS, keysAsRoot
	t.Cleanup(func() { keysFS, keysAsRoot = oldFS, oldRoot })
	keysFS = func() system.RootFS { return system.NewRootFS(root) }
	keysAsRoot = func() bool { return true }
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KIYESI_ETC", t.TempDir())
	return root
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

// kiyesi keys remove changes nothing: it says where the key is and gives
// the command for each file, matched by the key itself, for a person to
// review and run; --yes changes nothing either.
func TestKeysRemoveShowsTheCommandsAndChangesNothing(t *testing.T) {
	root := keysServer(t)
	rsa, fp := keyLine(t, "rsa")
	before, _ := os.ReadFile(filepath.Join(root, "root/.ssh/authorized_keys"))
	code, out, errOut := runCLI(t, "keys", "remove", fp, "--yes")
	if code != ExitOK {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	body := strings.Fields(rsa)[1]
	for _, want := range []string{
		"Kiyesi changes nothing on this server. It only suggests: you review each command and run it yourself.",
		"root (/root/.ssh/authorized_keys)",
		"ada (/home/ada/.ssh/authorized_keys)",
		"sudo sed -i '\\|" + body + "|d' /root/.ssh/authorized_keys",
		"sudo sed -i '\\|" + body + "|d' /home/ada/.ssh/authorized_keys",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	after, _ := os.ReadFile(filepath.Join(root, "root/.ssh/authorized_keys"))
	if string(after) != string(before) {
		t.Error("a file changed")
	}
	var got struct {
		Changed bool `json:"changed"`
		Steps   []struct{ Account, File, Command string }
	}
	code, out, _ = runCLI(t, "keys", "remove", fp, "--json")
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != ExitOK || got.Changed || len(got.Steps) != 2 {
		t.Errorf("json: %d %v %+v", code, err, got)
	}
}

// It warns, before the commands, when the key is the last one the person
// signs in with; a fingerprint that is not one, or not found, says so.
func TestKeysRemoveWarnsAboutYourLastKey(t *testing.T) {
	keysServer(t)
	_, fp := keyLine(t, "rsa")
	var out bytes.Buffer
	code := Execute([]string{"keys", "remove", fp}, IO{Out: &out, Err: &out, Environ: []string{"NO_COLOR=1", "SUDO_USER=ada"}})
	if code != ExitOK || !strings.Contains(out.String(), "It is the only key ada signs in with here") {
		t.Errorf("%d\n%s", code, out.String())
	}
	if code, _, errOut := runCLI(t, "keys", "remove", "nope"); code != ExitUsage || !strings.Contains(errOut, "is not a key's fingerprint") {
		t.Errorf("bad fingerprint: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, "keys", "remove", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); code != ExitUsage || !strings.Contains(errOut, "No account on this server has the key") {
		t.Errorf("unknown key: %d %q", code, errOut)
	}
}
