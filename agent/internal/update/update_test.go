package update

import (
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

func release(t *testing.T, s signer, bin []byte, tamper string) *httptest.Server {
	sum := sha256.Sum256(bin)
	sums := []byte(fmt.Sprintf("%s  kiyesi-linux-amd64\n%s  kiyesi-darwin-arm64\n", hex.EncodeToString(sum[:]), hex.EncodeToString(sum[:])))
	sig := s.sign(t, sums)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/VERSION":
			fmt.Fprintln(w, "0.24.0")
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
		src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64"}
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
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), OS: "freebsd", Arch: "amd64"}
	if _, _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "no kiyesi build for freebsd") {
		t.Errorf("unknown system: %v", err)
	}
	other := newSigner(t)
	src = Source{Base: srv.URL, Key: other.pub, HTTP: srv.Client(), OS: "linux", Arch: "amd64"}
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
