package cli

import (
	"os"
	"path/filepath"
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
