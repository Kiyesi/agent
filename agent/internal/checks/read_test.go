package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// A user can turn their .env into a link to a file only root may read, or a
// pipe that never ends, between the scan listing the folder and reading the
// file. Through the real file system, neither is read.
func TestReadUserFileRefusesLinksPipesAndHugeFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/shadow", "root:$6$secret\n")
	write("srv/app/.env", "DB_PASSWORD=x\n")
	write("srv/big/.env", strings.Repeat("A", readCap+1))
	if err := os.Symlink(filepath.Join(dir, "etc/shadow"), filepath.Join(dir, "srv/link.env")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "srv/pipe.env"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys := system.NewRootFS(dir)

	if data, err := readUserFile(fsys, "srv/app/.env"); err != nil || string(data) != "DB_PASSWORD=x\n" {
		t.Fatalf("a plain file: %q %v", data, err)
	}
	if data, err := readUserFile(fsys, "srv/link.env"); err == nil || strings.Contains(string(data), "secret") {
		t.Fatalf("read through a link: %q %v", data, err)
	}
	done := make(chan error, 1)
	go func() { _, err := readUserFile(fsys, "srv/pipe.env"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, errNotPlain) {
			t.Fatalf("a pipe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a pipe waited")
	}
	if _, err := readUserFile(fsys, "srv/big/.env"); !errors.Is(err, errTooBig) {
		t.Fatalf("a huge file: %v", err)
	}
}
