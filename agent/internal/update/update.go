package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// Release is what get.kiyesi.dev offers now.
type Release struct {
	Version string
	File    string
}

// Source is where releases come from, and the key that signs them.
type Source struct {
	Base string // https://get.kiyesi.dev
	Key  string
	HTTP *http.Client
	OS   string
	Arch string
	// Running is this program's version. Fetch takes only a release whose
	// signed version is newer, so an old signed release cannot be sent
	// back to replace a newer one.
	Running string
}

// DefaultSource is get.kiyesi.dev, or KIYESI_GET_URL.
func DefaultSource(goos, goarch string) Source {
	base := os.Getenv("KIYESI_GET_URL")
	if base == "" {
		base = "https://get.kiyesi.dev"
	}
	return Source{Base: strings.TrimRight(base, "/"), Key: ReleaseKey, HTTP: &http.Client{Timeout: 2 * time.Minute, CheckRedirect: httpsOnly}, OS: goos, Arch: goarch, Running: version.Version}
}

// httpsOnly follows a redirect only to another https address.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refused a redirect to %s: releases come only over https", req.URL.Redacted())
	}
	return nil
}

// checkBase refuses a release site that is not https. Plain http is taken
// only on this machine's own loopback address, which tests use.
func checkBase(base string) error {
	u, err := url.Parse(base)
	if err == nil && u.Scheme == "https" && u.Host != "" {
		return nil
	}
	if err == nil && u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}
	return fmt.Errorf("the release site must be an https address, not %q (check KIYESI_GET_URL)", base)
}

// ErrUnreachable means this network could not reach the release site at all.
var ErrUnreachable = errors.New("cannot reach the release site")

// retryWait is the pause before each new try. Tests shorten it.
var retryWait = []time.Duration{time.Second, 3 * time.Second}

func (s Source) get(ctx context.Context, name string, limit int64) ([]byte, error) {
	if err := checkBase(s.Base); err != nil {
		return nil, err
	}
	var resp *http.Response
	var err error
	// Three tries: a phone network or a waking laptop often fails once.
	for try := 0; ; try++ {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, s.Base+"/"+name, nil)
		if err != nil {
			return nil, err
		}
		resp, err = s.HTTP.Do(req)
		if err == nil || try >= len(retryWait) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(retryWait[try]):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, s.Base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s/%s answered %d", s.Base, name, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// Latest is the newest version, without downloading the program.
func (s Source) Latest(ctx context.Context) (string, error) {
	v, err := s.get(ctx, "VERSION", 64)
	return strings.TrimSpace(string(v)), err
}

// Fetch downloads the program for this machine and returns it only if the
// release's signature and the file's checksum both match, and the version
// the signature covers is newer than this one. VERSION, which is not
// signed, only says whether to look.
func (s Source) Fetch(ctx context.Context) (Release, []byte, error) {
	sums, err := s.get(ctx, "SHA256SUMS", 64<<10)
	if err != nil {
		return Release{}, nil, err
	}
	sig, err := s.get(ctx, "SHA256SUMS.sig", 64<<10)
	if err != nil {
		return Release{}, nil, err
	}
	if err := Verify(s.Key, Namespace, sums, sig); err != nil {
		return Release{}, nil, fmt.Errorf("%w. Nothing was changed. Tell security@kiyesi.dev", err)
	}
	file := AssetName(s.OS, s.Arch)
	signed, want := ParseSums(sums, file)
	if signed == "" {
		return Release{}, nil, errors.New("the release does not name its version in its signed list. Nothing was changed. Tell security@kiyesi.dev")
	}
	if !Newer(signed, s.Running) {
		return Release{}, nil, fmt.Errorf("the release offered is kiyesi %s, which is not newer than this kiyesi %s, so nothing was changed", signed, s.Running)
	}
	if want == "" {
		return Release{}, nil, fmt.Errorf("there is no kiyesi build for %s %s", s.OS, s.Arch)
	}
	bin, err := s.get(ctx, file, 200<<20)
	if err != nil {
		return Release{}, nil, err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != want {
		return Release{}, nil, errors.New("the downloaded program does not match its checksum. Nothing was changed")
	}
	return Release{Version: signed, File: file}, bin, nil
}

// ParseSums reads the signed list: a line "version 0.38.0", and a line
// "<sha256>  <file>" for each build. It returns the version and the
// checksum of file. Kiyesi 0.37.0 and older read only the checksum lines,
// whose second word is a file name, so they skip the version line.
func ParseSums(sums []byte, file string) (version, sum string) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		switch {
		case f[0] == "version" && validVersion(f[1]):
			version = f[1]
		case strings.TrimPrefix(f[1], "*") == file:
			sum = f[0]
		}
	}
	return version, sum
}

// ParseRelease reads the version and whether the release fixes a security
// problem ("security yes") from the signed list. Older kiyesi skip that
// line: its second word is not a file name.
func ParseRelease(sums []byte) (version string, security bool) {
	version, _ = ParseSums(sums, "")
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[0] == "security" && f[1] == "yes" {
			security = true
		}
	}
	return version, security
}

// Signed is the newest release as its signed list says: its version, and
// whether it fixes a security problem. Nothing is believed unsigned.
func (s Source) Signed(ctx context.Context) (version string, security bool, err error) {
	sums, err := s.get(ctx, "SHA256SUMS", 64<<10)
	if err != nil {
		return "", false, err
	}
	sig, err := s.get(ctx, "SHA256SUMS.sig", 64<<10)
	if err != nil {
		return "", false, err
	}
	if err := Verify(s.Key, Namespace, sums, sig); err != nil {
		return "", false, err
	}
	version, security = ParseRelease(sums)
	if version == "" {
		return "", false, errors.New("the release does not name its version in its signed list")
	}
	return version, security, nil
}

// validVersion is three numbers with dots, such as 0.38.0.
func validVersion(v string) bool {
	p := strings.Split(v, ".")
	if len(p) != 3 {
		return false
	}
	for _, n := range p {
		if n == "" || len(n) > 6 || strings.Trim(n, "0123456789") != "" {
			return false
		}
	}
	return true
}

// ErrPermission means the program's folder needs sudo to change.
var ErrPermission = errors.New("permission denied")

// Replace puts the new program where the running one is, in one step: a
// new file beside it, then a rename, so it is never half written.
func Replace(exe string, bin []byte) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".kiyesi-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return ErrPermission
		}
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil { // #nosec G302 -- a program everyone runs, as install.sh makes it
		return err
	}
	if err := swap(tmp.Name(), exe); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return ErrPermission
		}
		return err
	}
	return nil
}

// AssetName is a release's file for a system and processor, such as
// kiyesi-linux-amd64, or kiyesi-windows-amd64.exe on Windows.
func AssetName(goos, goarch string) string {
	name := fmt.Sprintf("kiyesi-%s-%s", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// Newer says whether version a is newer than b (both like 0.22.0).
func Newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out[i] = n
	}
	return out
}
