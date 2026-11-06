package system

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

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
