package system

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cacheFrom was the size from which 0.48.1 dropped a file's cache; files
// that large must still read, seek and list as before.
const cacheFrom = 256 << 10

func TestLargeFilesAreReadNormallyAndLeaveNoCache(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, cacheFrom+1)
	big[len(big)-1] = 'z'
	if err := os.WriteFile(filepath.Join(dir, "big.log"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRootFS(dir)
	b, err := r.ReadFile("big.log")
	if err != nil || len(b) != len(big) || b[len(b)-1] != 'z' {
		t.Fatalf("read %d bytes, %v", len(b), err)
	}
	// Still a file that seeks, as the log readers need.
	f, err := r.Open("big.log")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := f.(io.Seeker)
	if !ok {
		t.Fatal("the file no longer seeks")
	}
	if at, err := s.Seek(-1, io.SeekEnd); err != nil || at != int64(cacheFrom) {
		t.Fatalf("seek %d %v", at, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Folders still list.
	if ents, err := fs.ReadDir(r, "."); err != nil || len(ents) != 1 {
		t.Fatalf("list %v %v", ents, err)
	}
	g, err := r.OpenNoFollow("big.log")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := io.Copy(io.Discard, g); n != int64(len(big)) {
		t.Errorf("read %d through OpenNoFollow", n)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEveryFileReadLeavesNoCacheButSharedSettings(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"srv/app/package-lock.json", "var/lib/dpkg/status", "usr/bin/ps", "etc/passwd", "etc/ssh/sshd_config", "empty"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		data := []byte("x\n")
		if p == "empty" {
			data = nil
		}
		if err := os.WriteFile(filepath.Join(dir, p), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var dropped []string
	drop = func(f *os.File) {
		rel, _ := filepath.Rel(dir, f.Name())
		dropped = append(dropped, filepath.ToSlash(rel))
	}
	defer func() { drop = dropCache }()
	r := NewRootFS(dir)
	for _, p := range []string{"srv/app/package-lock.json", "var/lib/dpkg/status", "etc/passwd", "empty"} {
		if _, err := r.ReadFile(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"usr/bin/ps", "etc/ssh/sshd_config"} {
		f, err := r.OpenNoFollow(p)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	// A folder opened to list is not a file to drop.
	if _, err := fs.ReadDir(r, "srv"); err != nil {
		t.Fatal(err)
	}
	d, err := r.Open("srv")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	want := "srv/app/package-lock.json var/lib/dpkg/status usr/bin/ps"
	if got := strings.Join(dropped, " "); got != want {
		t.Errorf("dropped %q, want %q: small files too, never /etc, never an empty file or a folder", got, want)
	}
}
