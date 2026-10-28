package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// noticeState is what the daily check remembers between commands.
type noticeState struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
	Security  bool      `json:"security"`
	ToldAt    time.Time `json:"told_at"`
}

// NoticePath is where the daily check is remembered: Kiyesi's own folder
// as root, the person's cache folder otherwise.
func NoticePath() string {
	if os.Geteuid() == 0 {
		return "/var/lib/kiyesi/update-check.json"
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "kiyesi", "update-check.json")
}

// Notice is the one line to print when a newer kiyesi is out, at most once
// a day, or "". It asks get.kiyesi.dev at most once a day too, and believes
// only the signed list. It never updates anything by itself, and any
// failure (no network, no folder) is silent: it is only a reminder.
func Notice(ctx context.Context, s Source, path string, now time.Time) string {
	if path == "" {
		return ""
	}
	var st noticeState
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- Kiyesi's own state file
		_ = json.Unmarshal(b, &st)
	}
	if now.Sub(st.CheckedAt) >= 24*time.Hour || now.Before(st.CheckedAt) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		v, sec, err := s.Signed(ctx)
		cancel()
		// Remembered either way, so a server without the internet does not
		// wait three seconds on every command.
		st.CheckedAt = now
		if err == nil {
			st.Latest, st.Security = v, sec
		}
	}
	line := ""
	if st.Latest != "" && Newer(st.Latest, s.Running) && now.Sub(st.ToldAt) >= 24*time.Hour {
		if st.Security {
			line = fmt.Sprintf("kiyesi %s is out and fixes a security problem: run sudo kiyesi update", st.Latest)
		} else {
			line = fmt.Sprintf("kiyesi %s is out: run sudo kiyesi update", st.Latest)
		}
		st.ToldAt = now
	}
	if b, err := json.Marshal(st); err == nil {
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		_ = os.WriteFile(path, b, 0o600)
	}
	return line
}
