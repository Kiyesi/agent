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
	"os"
	"path/filepath"
	"strings"
	"time"
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
}

// DefaultSource is get.kiyesi.dev, or KIYESI_GET_URL.
func DefaultSource(goos, goarch string) Source {
	base := os.Getenv("KIYESI_GET_URL")
	if base == "" {
		base = "https://get.kiyesi.dev"
	}
	return Source{Base: strings.TrimRight(base, "/"), Key: ReleaseKey, HTTP: &http.Client{Timeout: 2 * time.Minute}, OS: goos, Arch: goarch}
}

// ErrUnreachable means this network could not reach the release site at all.
var ErrUnreachable = errors.New("cannot reach the release site")

// retryWait is the pause before each new try. Tests shorten it.
var retryWait = []time.Duration{time.Second, 3 * time.Second}

func (s Source) get(ctx context.Context, name string, limit int64) ([]byte, error) {
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
// release's signature and the file's checksum both match.
func (s Source) Fetch(ctx context.Context) (Release, []byte, error) {
	version, err := s.Latest(ctx)
	if err != nil {
		return Release{}, nil, err
	}
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
	file := fmt.Sprintf("kiyesi-%s-%s", s.OS, s.Arch)
	want := ""
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && strings.TrimPrefix(f[1], "*") == file {
			want = f[0]
		}
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
	return Release{Version: version, File: file}, bin, nil
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
	if err := os.Rename(tmp.Name(), exe); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return ErrPermission
		}
		return err
	}
	return nil
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
