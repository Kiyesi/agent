package fix

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretOnDisk makes a real folder with a secret file Kiyesi will close, and
// a file a user must never reach through it (standing in for /etc/shadow).
func secretOnDisk(t *testing.T) (dir, secret, target string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret = filepath.Join(dir, ".env")
	target = filepath.Join(dir, "shadow")
	for p, m := range map[string]fs.FileMode{secret: 0o644, target: 0o600} {
		if err := os.WriteFile(p, []byte("x\n"), m); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	return dir, secret, target
}

func modeOf(t *testing.T, p string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// closeOnDisk runs the change the secret-files fix makes, through the real
// host, and returns its record.
func closeOnDisk(t *testing.T, s *Store, secret string) *Record {
	t.Helper()
	rec, err := s.Begin("secret-files", "Secret files closed to other users", "ada", true)
	if err != nil {
		t.Fatal(err)
	}
	c := &Changes{h: RealHost{}, s: s, rec: rec}
	info, err := os.Lstat(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Chmod(secret, info, 0o640); err != nil {
		t.Fatal(err)
	}
	return rec
}

func swapForLink(t *testing.T, path, to string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(to, path); err != nil {
		t.Fatal(err)
	}
}

func TestUndoPutsTheModeBackOnTheSameFile(t *testing.T) {
	_, secret, _ := secretOnDisk(t)
	s := store(t)
	rec := closeOnDisk(t, s, secret)
	if m := modeOf(t, secret); m != 0o640 {
		t.Fatalf("mode after the fix = %o", m)
	}
	got, err := s.Get(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Files[0].ID == nil {
		t.Fatal("the record does not name the file it changed")
	}
	if err := s.Undo(context.Background(), RealHost{}, got); err != nil {
		t.Fatal(err)
	}
	if m := modeOf(t, secret); m != 0o644 {
		t.Fatalf("mode after undo = %o", m)
	}
}

// A user who owns the folder swaps their secret file for a link to a file
// only root may read, then waits for root to run kiyesi fix undo: the old,
// wider mode must never land on the link's target.
func TestUndoRefusesALinkSwappedInForTheFile(t *testing.T) {
	_, secret, target := secretOnDisk(t)
	s := store(t)
	rec := closeOnDisk(t, s, secret)
	swapForLink(t, secret, target)
	err := s.Undo(context.Background(), RealHost{}, rec)
	if err == nil || !strings.Contains(err.Error(), "is a link now") {
		t.Fatalf("undo through a link: %v", err)
	}
	if m := modeOf(t, target); m != 0o600 {
		t.Fatalf("the link's target changed to %o", m)
	}
	if rec.UndoneAt != nil {
		t.Fatal("marked undone")
	}
}

// A different plain file in its place, such as a hard link to another file,
// is refused too: it is not the file the fix changed.
func TestUndoRefusesADifferentFileInItsPlace(t *testing.T) {
	_, secret, target := secretOnDisk(t)
	s := store(t)
	rec := closeOnDisk(t, s, secret)
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, secret); err != nil {
		t.Fatal(err)
	}
	err := s.Undo(context.Background(), RealHost{}, rec)
	if err == nil || !strings.Contains(err.Error(), "no longer the file Kiyesi looked at") {
		t.Fatalf("undo on another file: %v", err)
	}
	if m := modeOf(t, target); m != 0o600 {
		t.Fatalf("the other file changed to %o", m)
	}
}

// The fix looks at the file, then changes it: a link swapped in between the
// two is left alone.
func TestFixRefusesALinkSwappedInAfterItLooked(t *testing.T) {
	_, secret, target := secretOnDisk(t)
	s := store(t)
	rec, err := s.Begin("secret-files", "Secret files closed to other users", "ada", true)
	if err != nil {
		t.Fatal(err)
	}
	c := &Changes{h: RealHost{}, s: s, rec: rec}
	seen, err := os.Lstat(secret)
	if err != nil {
		t.Fatal(err)
	}
	swapForLink(t, secret, target)
	if err := c.Chmod(secret, seen, 0o640); err == nil || !strings.Contains(err.Error(), "is a link now") {
		t.Fatalf("chmod through a link: %v", err)
	}
	if m := modeOf(t, target); m != 0o600 {
		t.Fatalf("the link's target changed to %o", m)
	}
}

func TestUndoRefusesWhereOthersCanWriteTheFolder(t *testing.T) {
	dir, secret, _ := secretOnDisk(t)
	s := store(t)
	rec := closeOnDisk(t, s, secret)
	if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- the test's own folder, opened to every user on purpose
		t.Fatal(err)
	}
	err := s.Undo(context.Background(), RealHost{}, rec)
	if err == nil || !strings.Contains(err.Error(), "can be written to by every user") || !strings.Contains(err.Error(), "sudo chmod 0644 "+secret) {
		t.Fatalf("undo in an open folder: %v", err)
	}
	if m := modeOf(t, secret); m != 0o640 {
		t.Fatalf("mode = %o", m)
	}
}

// A record from 0.37.0 or older does not say which file it changed, so undo
// says how to put the mode back by hand instead.
func TestUndoOfAnOldRecordSaysHowToDoItByHand(t *testing.T) {
	_, secret, _ := secretOnDisk(t)
	s := store(t)
	rec, err := s.Begin("secret-files", "Secret files closed to other users", "ada", true)
	if err != nil {
		t.Fatal(err)
	}
	rec.Files = []Saved{{Path: secret, Existed: true, Mode: 0o644, ModeOnly: true}}
	err = s.Undo(context.Background(), RealHost{}, rec)
	if err == nil || !strings.Contains(err.Error(), "older than 0.38.0") || !strings.Contains(err.Error(), "sudo chmod 0644 "+secret) {
		t.Fatalf("undo of an old record: %v", err)
	}
}

func TestWriteFileLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.conf")
	// A link at the name the old code wrote through first is never followed.
	trap := filepath.Join(dir, "trap")
	if err := os.Symlink(trap, filepath.Join(dir, ".kiyesi-a.conf")); err != nil {
		t.Fatal(err)
	}
	if err := (RealHost{}).WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(trap); err == nil {
		t.Fatal("wrote through the link")
	}
	if m := modeOf(t, p); m != 0o600 {
		t.Fatalf("mode = %o", m)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("left behind: %v", entries)
	}
}
