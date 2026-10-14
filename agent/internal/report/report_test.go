package report

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveKeepsTheLast30AndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i := range 35 {
		if _, err := Save(dir, day.AddDate(0, 0, i), fmt.Sprint("report ", i)); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != Keep {
		t.Fatalf("kept %d files, want %d", len(entries), Keep)
	}
	if entries[0].Name() != "report-2026-09-06.txt" {
		t.Errorf("oldest kept = %s", entries[0].Name())
	}
	info, err := os.Stat(filepath.Join(dir, "report-2026-10-05.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSameDayReplacesTheReport(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	_, _ = Save(dir, day, "first")
	p, err := Save(dir, day.Add(3*time.Hour), "second")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if string(data) != "second" || filepath.Base(p) != "report-2026-10-08.txt" {
		t.Errorf("%s = %q", p, data)
	}
}

func TestDirWithoutRoot(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/state")
	if got := Dir(false); got != "/tmp/state/kiyesi" {
		t.Errorf("Dir = %q", got)
	}
	if got := Dir(true); got != "/var/lib/kiyesi" {
		t.Errorf("Dir(root) = %q", got)
	}
}
