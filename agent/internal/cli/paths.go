package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Where a connected agent keeps its settings and its outbox. Tests point
// these elsewhere with KIYESI_ETC and KIYESI_STATE.
func etcDir() string {
	if d := os.Getenv("KIYESI_ETC"); d != "" {
		return d
	}
	return "/etc/kiyesi"
}

func stateDir() string {
	if d := os.Getenv("KIYESI_STATE"); d != "" {
		return d
	}
	// Beside a managed service (container mode), the token is in the
	// environment and /var/lib is often not writable: use the temp folder,
	// the same for kiyesi agent and kiyesi run in that container.
	if os.Getenv("KIYESI_TOKEN") != "" {
		return filepath.Join(os.TempDir(), "kiyesi")
	}
	return "/var/lib/kiyesi"
}

func tokenPath() string     { return filepath.Join(etcDir(), "token") }
func agentConfPath() string { return filepath.Join(etcDir(), "agent.yaml") }
func outboxDir() string     { return filepath.Join(stateDir(), "outbox") }

// teamHomePath keeps the team's home country, as the service last said it.
func teamHomePath() string { return filepath.Join(stateDir(), "team-home-country") }

// teamHome is the team's home country as the service last said it, or "".
func teamHome() string {
	data, err := os.ReadFile(teamHomePath()) // #nosec G304 -- the agent's own state file
	if err != nil {
		return ""
	}
	code := strings.TrimSpace(string(data))
	if len(code) != 2 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return ""
	}
	return code
}

// saveTeamHome keeps the team's choice for the next scans; "" clears it.
func saveTeamHome(code string) error {
	if code == teamHome() {
		return nil
	}
	if code == "" {
		if err := os.Remove(teamHomePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(teamHomePath(), []byte(code+"\n"), 0o600)
}
