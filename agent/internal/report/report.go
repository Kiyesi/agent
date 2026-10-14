// Package report saves the full report file and keeps the last 30.
package report

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Keep is how many report files are kept.
const Keep = 30

// Dir returns where reports and the scan's state are kept: /var/lib/kiyesi
// for root, or the user's state folder otherwise.
func Dir(root bool) string {
	if root {
		return "/var/lib/kiyesi"
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "kiyesi")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "kiyesi")
	}
	return filepath.Join(home, ".local", "state", "kiyesi")
}

// Save writes the report for the day, readable only by its owner, and
// removes the oldest reports beyond Keep. It returns the file's path.
func Save(dir string, day time.Time, text string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "report-"+day.Format("2006-01-02")+".txt")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	prune(dir)
	return path, nil
}

func prune(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var reports []string
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, "report-") && strings.HasSuffix(n, ".txt") && !e.IsDir() {
			reports = append(reports, n)
		}
	}
	sort.Strings(reports) // dates sort in order
	for len(reports) > Keep {
		_ = os.Remove(filepath.Join(dir, reports[0]))
		reports = reports[1:]
	}
}
