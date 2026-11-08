package system

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKillLog(t *testing.T) {
	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "kills.json")
	l := KillLog{Path: path}
	// Never watched: no record yet.
	if since, kills, err := l.Load(now); err != nil || !since.IsZero() || len(kills) != 0 {
		t.Fatalf("empty: %v %v %v", since, kills, err)
	}
	// The first watch is written, readable by its owner only.
	if err := l.Record(now, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", info, err)
	}
	// Nothing new: nothing written.
	before := info.ModTime()
	time.Sleep(10 * time.Millisecond)
	if err := l.Record(now.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); !info.ModTime().Equal(before) {
		t.Error("written with nothing new")
	}
	// A kill counts once, however often it is seen.
	node := Kill{Process: "node", At: now.Add(-time.Hour)}
	_ = l.Record(now, []Kill{node})
	_ = l.Record(now, []Kill{node})
	since, kills, _ := l.Load(now)
	if !since.Equal(now) || len(kills) != 1 || kills[0] != node {
		t.Fatalf("since %v kills %+v", since, kills)
	}
	// A day later it is gone; watching goes on.
	since, kills, _ = l.Load(now.Add(25 * time.Hour))
	if since.IsZero() || len(kills) != 0 {
		t.Errorf("a day later: %v %+v", since, kills)
	}
	// A damaged record is started again.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if since, _, err := l.Load(now); err != nil || !since.IsZero() {
		t.Errorf("damaged: %v %v", since, err)
	}
}
