package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestVerifyAcceptsWhatSshKeygenSigns(t *testing.T) {
	msg, _ := os.ReadFile("testdata/message")
	sig, _ := os.ReadFile("testdata/message.sig")
	key, _ := os.ReadFile("testdata/test-key.pub")
	if err := Verify(string(key), Namespace, msg, sig); err != nil {
		t.Fatalf("a real ssh-keygen signature was refused: %v", err)
	}
	if Verify(string(key), Namespace, append(msg, 'x'), sig) == nil {
		t.Error("a changed message passed")
	}
	if Verify(string(key), "other-purpose", msg, sig) == nil {
		t.Error("another namespace passed")
	}
	if Verify(ReleaseKey, Namespace, msg, sig) == nil {
		t.Error("a signature by another key passed as the release key's")
	}
}

func TestTheBuiltInKeyIsTheReleaseKey(t *testing.T) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ReleaseKey))
	if err != nil || k.Type() != "ssh-ed25519" {
		t.Fatalf("%v %v", k, err)
	}
}

// signer makes signatures the way ssh-keygen -Y sign does, for a stand-in get.kiyesi.dev.
type signer struct {
	pub  string
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T) signer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	return signer{pub: string(ssh.MarshalAuthorizedKey(sp)), priv: priv}
}

func (s signer) sign(t *testing.T, msg []byte) []byte {
	h := sha512.Sum512(msg)
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{[6]byte{'S', 'S', 'H', 'S', 'I', 'G'}, Namespace, "", "sha512", h[:]})
	sshSigner, err := ssh.NewSignerFromKey(s.priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshSigner.Sign(rand.Reader, signed)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}{[6]byte{'S', 'S', 'H', 'S', 'I', 'G'}, 1, sshSigner.PublicKey().Marshal(), Namespace, "", "sha512", ssh.Marshal(sig)})
	return armor(blob)
}

// newSums is the signed list as scripts/build-get.sh makes it from 0.38.0:
// the version first, then a checksum line per build.
func newSums(version string, bin []byte) []byte {
	sum := hex.EncodeToString(func() []byte { s := sha256.Sum256(bin); return s[:] }())
	head := ""
	if version != "" {
		head = "version " + version + "\n"
	}
	return []byte(fmt.Sprintf("%s%s  kiyesi-linux-amd64\n%s  kiyesi-darwin-arm64\n", head, sum, sum))
}

func release(t *testing.T, s signer, bin []byte, tamper string) *httptest.Server {
	return releaseOf(t, s, bin, tamper, "0.24.0", "0.24.0")
}

// releaseOf serves a release whose unsigned VERSION file says one version
// and whose signed list says another.
func releaseOf(t *testing.T, s signer, bin []byte, tamper, unsigned, signed string) *httptest.Server {
	sums := newSums(signed, bin)
	sig := s.sign(t, sums)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/VERSION":
			fmt.Fprintln(w, unsigned)
		case "/SHA256SUMS":
			if tamper == "sums" {
				w.Write(append(sums, '\n', 'x'))
				return
			}
			w.Write(sums)
		case "/SHA256SUMS.sig":
			w.Write(sig)
		case "/kiyesi-linux-amd64", "/kiyesi-darwin-arm64":
			if tamper == "binary" {
				w.Write(append(bin, 0))
				return
			}
			w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestFetchChecksTheSignatureAndTheChecksum(t *testing.T) {
	s := newSigner(t)
	bin := []byte("#!/bin/sh\necho new kiyesi\n")
	for _, tc := range []struct{ tamper, want string }{{"", ""}, {"sums", "signature does not match"}, {"binary", "checksum"}} {
		srv := release(t, s, bin, tc.tamper)
		src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64", Running: "0.23.0"}
		r, got, err := src.Fetch(context.Background())
		srv.Close()
		if tc.want == "" {
			if err != nil || r.Version != "0.24.0" || string(got) != string(bin) {
				t.Errorf("good release: %v %v", r, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.tamper, err)
		}
	}
	srv := release(t, s, bin, "")
	defer srv.Close()
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "freebsd", Arch: "amd64", Running: "0.23.0"}
	if _, _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "no kiyesi build for freebsd") {
		t.Errorf("unknown system: %v", err)
	}
	other := newSigner(t)
	src = Source{Base: srv.URL, Key: other.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64", Running: "0.23.0"}
	if _, _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Errorf("another key: %v", err)
	}
}

func TestReplaceSwapsTheFileInOneStep(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "kiyesi")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Replace(exe, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(exe)
	info, _ := os.Stat(exe)
	if string(got) != "new" || info.Mode().Perm() != 0o755 {
		t.Errorf("%q %v", got, info.Mode())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
	if os.Getuid() != 0 {
		locked := filepath.Join(t.TempDir(), "locked")
		_ = os.Mkdir(locked, 0o555)
		if err := Replace(filepath.Join(locked, "kiyesi"), []byte("x")); !errors.Is(err, ErrPermission) {
			t.Errorf("read-only folder: %v", err)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.24.0", "0.23.0", true}, {"0.23.0", "0.23.0", false}, {"0.22.9", "0.23.0", false}, {"1.0.0", "0.99.9", true}, {"0.10.0", "0.9.0", true}} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestAFailedConnectionIsTriedThreeTimesThenSaysUnreachable(t *testing.T) {
	old := retryWait
	retryWait = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryWait = old })
	tries := 0
	src := Source{Base: "https://get.example.test", HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		tries++
		return nil, errors.New("dial tcp [2606:4700::1]:443: connect: no route to host")
	})}}
	if _, err := src.Latest(context.Background()); !errors.Is(err, ErrUnreachable) || tries != 3 {
		t.Errorf("%d tries: %v", tries, err)
	}
	// A failure once, then an answer: the second try wins.
	tries = 0
	src.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		tries++
		if tries == 1 {
			return nil, errors.New("connection reset")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("0.30.0\n")), Request: r}, nil
	})}
	if v, err := src.Latest(context.Background()); err != nil || v != "0.30.0" {
		t.Errorf("%q %v", v, err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An attacker who controls the network or the site can serve an older
// release, signed in its day, with VERSION saying it is new. The version
// inside the signature decides, so it is refused.
func TestFetchRefusesAnOlderOrTheSameSignedRelease(t *testing.T) {
	s := newSigner(t)
	bin := []byte("old kiyesi")
	for _, signed := range []string{"0.22.0", "0.23.0"} {
		srv := releaseOf(t, s, bin, "", "9.9.9", signed)
		src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64", Running: "0.23.0"}
		_, _, err := src.Fetch(context.Background())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "kiyesi "+signed+", which is not newer than this kiyesi 0.23.0") {
			t.Errorf("signed %s: %v", signed, err)
		}
	}
}

func TestFetchReportsTheSignedVersionNotTheUnsignedOne(t *testing.T) {
	s := newSigner(t)
	srv := releaseOf(t, s, []byte("new"), "", "0.99.0", "0.24.0")
	defer srv.Close()
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64", Running: "0.23.0"}
	r, _, err := src.Fetch(context.Background())
	if err != nil || r.Version != "0.24.0" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFetchRefusesASignedListWithoutAVersion(t *testing.T) {
	s := newSigner(t)
	srv := releaseOf(t, s, []byte("new"), "", "0.24.0", "")
	defer srv.Close()
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64", Running: "0.23.0"}
	if _, _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "does not name its version") {
		t.Fatal(err)
	}
}

// oldParse is how kiyesi 0.37.0 found its checksum in SHA256SUMS, copied
// from that release's update.Fetch. Agents already installed run it, so the
// new list must still give them the right checksum.
func oldParse(sums []byte, file string) string {
	want := ""
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && strings.TrimPrefix(f[1], "*") == file {
			want = f[0]
		}
	}
	return want
}

func TestTheNewSignedListStillWorksForKiyesi037(t *testing.T) {
	bin := []byte("kiyesi 0.38.0")
	sum := sha256.Sum256(bin)
	sums := newSums("0.38.0", bin)
	if got := oldParse(sums, "kiyesi-linux-amd64"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("0.37.0 reads %q", got)
	}
	if v, got := ParseSums(sums, "kiyesi-linux-amd64"); v != "0.38.0" || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("%q %q", v, got)
	}
}

func TestReleasesComeOnlyOverHTTPS(t *testing.T) {
	for _, base := range []string{"http://get.kiyesi.dev", "ftp://get.kiyesi.dev", "get.kiyesi.dev", "http://10.0.0.1"} {
		src := Source{Base: base, HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			t.Fatalf("%s was asked", base)
			return nil, nil
		})}, Running: "0.23.0"}
		if _, err := src.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "must be an https address") {
			t.Errorf("%s: %v", base, err)
		}
	}
	t.Setenv("KIYESI_GET_URL", "http://get.example.test")
	if _, err := DefaultSource("linux", "amd64").Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "KIYESI_GET_URL") {
		t.Errorf("KIYESI_GET_URL over http: %v", err)
	}
}

func TestARedirectToPlainHTTPIsRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "0.99.0") }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/VERSION", http.StatusFound)
	}))
	defer tls.Close()
	c := tls.Client()
	c.CheckRedirect = DefaultSource("linux", "amd64").HTTP.CheckRedirect
	src := Source{Base: tls.URL, HTTP: c}
	if _, err := src.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "only over https") {
		t.Fatal(err)
	}
}

// Each system's download keeps its name; Windows' ends in .exe.
func TestAssetNames(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   "kiyesi-linux-amd64",
		"darwin":  "kiyesi-darwin-amd64",
		"windows": "kiyesi-windows-amd64.exe",
	} {
		if got := AssetName(goos, "amd64"); got != want {
			t.Errorf("%s: %s, want %s", goos, got, want)
		}
	}
}
