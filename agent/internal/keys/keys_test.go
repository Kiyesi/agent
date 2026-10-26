package keys

import (
	"os"
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
