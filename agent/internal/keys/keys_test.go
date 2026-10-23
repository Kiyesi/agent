package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func pub(t *testing.T, name string) (line, fp string) {
	t.Helper()
	l, err := os.ReadFile("testdata/" + name + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.ReadFile("testdata/" + name + ".fp")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(l)), strings.TrimSpace(string(f))
}

func TestFingerprintMatchesSshKeygen(t *testing.T) {
	for _, name := range []string{"ed25519", "rsa"} {
		line, want := pub(t, name)
		k, ok := ParseLine(line)
		if !ok || k.Fingerprint != want {
			t.Errorf("%s: fingerprint %q, want %q as ssh-keygen -l prints it", name, k.Fingerprint, want)
		}
		if !ValidFingerprint(k.Fingerprint) {
			t.Errorf("%s: %q is not valid", name, k.Fingerprint)
		}
	}
}

func TestParseLineWithOptionsAndComments(t *testing.T) {
	line, fp := pub(t, "ed25519")
	k, ok := ParseLine(`from="10.0.0.0/8",command="echo hi; exit" ` + line)
	if !ok || k.Fingerprint != fp || k.Comment != "ada@laptop" || !k.Restricted || k.Type != "ssh-ed25519" {
		t.Fatalf("got %+v", k)
	}
	for _, bad := range []string{"", "# a comment", "ssh-ed25519 not-base64!!", "garbage line", "ssh-ed25519"} {
		if _, ok := ParseLine(bad); ok {
			t.Errorf("%q read as a key", bad)
		}
	}
	// A comment is kept printable and short.
	k, _ = ParseLine(line[:strings.LastIndex(line, " ")] + " evil\x1b[2J" + strings.Repeat("x", 300))
	if strings.ContainsRune(k.Comment, 0x1b) || len(k.Comment) > 100 {
		t.Errorf("comment = %q", k.Comment)
	}
}

func TestReadEveryLoginAccount(t *testing.T) {
	ed, edFP := pub(t, "ed25519")
	rsa, rsaFP := pub(t, "rsa")
	changed := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	fsys := fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0:root:/root:/bin/bash\n" +
			"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n" +
			"git:x:998:998::/home/git:/usr/bin/git-shell\n" +
			"ada:x:1000:1000::/home/ada:/bin/bash\n" +
			"svc:x:999:999::/home/svc:/usr/sbin/nologin\n")},
		"root/.ssh/authorized_keys":     {Data: []byte(ed + "\n"), ModTime: changed},
		"home/ada/.ssh/authorized_keys": {Data: []byte("# mine\n" + ed + "\n" + rsa + "\n"), ModTime: changed},
		"home/git/.ssh/authorized_keys": {Data: []byte(`command="gitserve" ` + rsa + "\n"), ModTime: changed},
		// No login shell: its keys cannot open a shell, and are left out.
		"home/svc/.ssh/authorized_keys": {Data: []byte(ed + "\n")},
	}
	ks := Read(fsys)
	var got []string
	for _, k := range ks {
		got = append(got, k.User+" "+k.Fingerprint)
		if !k.ChangedAt.Equal(changed) {
			t.Errorf("%s changed_at = %v", k.User, k.ChangedAt)
		}
	}
	want := []string{"ada " + rsaFP, "ada " + edFP, "git " + rsaFP, "root " + edFP}
	if strings.Join(got, "\n") != strings.Join(sortedFPs(want), "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(sortedFPs(want), "\n"))
	}
	for _, k := range ks {
		if k.User == "git" && !k.Restricted {
			t.Error("git's key has a command= option and should read as limited")
		}
	}
}

// sortedFPs orders "user fingerprint" lines as Read does: by user, then fingerprint.
func sortedFPs(lines []string) []string {
	out := append([]string(nil), lines...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestPlanFindsEveryFile(t *testing.T) {
	ed, edFP := pub(t, "ed25519")
	rsa, _ := pub(t, "rsa")
	fsys := fstest.MapFS{
		"etc/passwd":                     {Data: []byte("root:x:0:0:root:/root:/bin/bash\nada:x:1000:1000::/home/ada:/bin/bash\n")},
		"root/.ssh/authorized_keys":      {Data: []byte(ed + "\n")},
		"home/ada/.ssh/authorized_keys":  {Data: []byte(rsa + "\n")},
		"home/ada/.ssh/authorized_keys2": {Data: []byte(`from="1.2.3.4" ` + ed + "\n")},
	}
	plan := Plan(fsys, edFP)
	if len(plan) != 2 || plan[0].Account.Name != "root" || plan[1].Path != "/home/ada/.ssh/authorized_keys2" || plan[1].Lines[0] != `from="1.2.3.4" `+ed {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestEditRemovesOnlyThoseLines(t *testing.T) {
	data := []byte("# keys\nssh-ed25519 AAAA a\nssh-rsa BBBB b\r\nssh-ed25519 AAAA a\n")
	got := string(Edit(data, []string{"ssh-ed25519 AAAA a", "ssh-rsa BBBB b"}, nil))
	if got != "# keys\n" {
		t.Fatalf("got %q", got)
	}
	got = string(Edit([]byte("# keys\n"), nil, []string{"ssh-rsa BBBB b", "ssh-rsa BBBB b"}))
	if got != "# keys\nssh-rsa BBBB b\n" {
		t.Fatalf("adding back: %q", got)
	}
	if got := string(Edit([]byte("x\n"), nil, []string{"x"})); got != "x\n" {
		t.Fatalf("a line already there is not added twice: %q", got)
	}
}

func TestEditOwnChangesOnlyAPlainFileItOwns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as an ordinary account")
	}
	dir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(p, []byte("ssh-ed25519 AAAA a\nssh-rsa BBBB b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EditOwn(p, []string{"ssh-rsa BBBB b"}, nil); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(p); string(data) != "ssh-ed25519 AAAA a\n" {
		t.Fatalf("file = %q", data)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 kept", info.Mode().Perm())
	}

	// A link is left alone, and its target is untouched.
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("ssh-rsa BBBB b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(p)
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if err := EditOwn(p, []string{"ssh-rsa BBBB b"}, nil); err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("err = %v, want a link refused", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "ssh-rsa BBBB b\n" {
		t.Fatal("the link's target changed")
	}

	// A folder others can write to is refused.
	_ = os.Remove(p)
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EditOwn(p, []string{"x"}, nil); err == nil || !strings.Contains(err.Error(), "others can write") {
		t.Fatalf("err = %v", err)
	}
	_ = os.Chmod(dir, 0o700)

	// Only authorized_keys files.
	if err := EditOwn(filepath.Join(dir, "config"), nil, []string{"x"}); err == nil {
		t.Fatal("a file other than authorized_keys was changed")
	}
}

func TestEditOwnFromRefusesRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to show it refuses root")
	}
	if err := EditOwnFrom(strings.NewReader(`{}`)); err == nil {
		t.Fatal("ran as root")
	}
}
