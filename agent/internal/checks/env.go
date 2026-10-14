package checks

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// Env is what every check receives: the system to read, the settings, and
// facts that several checks share, read once per scan.
type Env struct {
	Sys *system.System
	Cfg config.Config
	// ReuseSlowFor lets a slow check reuse its last result for this long.
	// The background agent sets it; a scan run by hand never does.
	ReuseSlowFor time.Duration

	containersOnce sync.Once
	containers     []system.Container
	containersErr  error

	listenersOnce sync.Once
	listeners     []Listener
	listenersErr  error

	firewallOnce sync.Once
	firewall     Firewall

	sshOnce sync.Once
	ssh     SSH

	settingsOnce sync.Once
	settings     Settings

	serverOnce sync.Once
	server     serverPlace

	databasesOnce sync.Once
	databases     []dbConn
}

// NewEnv returns an Env for one scan.
func NewEnv(sys *system.System, cfg config.Config) *Env { return &Env{Sys: sys, Cfg: cfg} }

// Containers returns every container, or none when Docker is not installed.
func (e *Env) Containers(ctx context.Context) ([]system.Container, error) {
	e.containersOnce.Do(func() {
		if e.Sys.Docker == nil {
			return
		}
		e.containers, e.containersErr = e.Sys.Docker.Containers(ctx)
	})
	return e.containers, e.containersErr
}

// Listeners returns the TCP ports listening on public addresses.
func (e *Env) Listeners() ([]Listener, error) {
	e.listenersOnce.Do(func() { e.listeners, e.listenersErr = readListeners(e.Sys.FS) })
	return e.listeners, e.listenersErr
}

// Firewall returns what is known about the firewall on this server.
func (e *Env) Firewall(ctx context.Context) Firewall {
	e.firewallOnce.Do(func() { e.firewall = readFirewall(ctx, e.Sys) })
	return e.firewall
}

// SSH returns the SSH server's login settings.
func (e *Env) SSH(ctx context.Context) SSH {
	e.sshOnce.Do(func() { e.ssh = readSSH(ctx, e.Sys) })
	return e.ssh
}

// remembered returns a check's last result from the state file, if it is
// younger than ReuseSlowFor.
func (e *Env) remembered(id string) (Result, bool) {
	if e.ReuseSlowFor <= 0 || e.Sys.State == nil {
		return Result{}, false
	}
	state, err := e.Sys.State.Load()
	if err != nil {
		return Result{}, false
	}
	at, err := time.Parse(time.RFC3339, state["result-at/"+id])
	if err != nil || e.Sys.Now().Sub(at) > e.ReuseSlowFor {
		return Result{}, false
	}
	var r Result
	if json.Unmarshal([]byte(state["result/"+id]), &r) != nil {
		return Result{}, false
	}
	return r, true
}

// remember keeps a check's result in the state file for later scans.
func (e *Env) remember(id string, r Result) {
	if e.ReuseSlowFor <= 0 || e.Sys.State == nil || r.Status == StatusSkip {
		return
	}
	state, err := e.Sys.State.Load()
	if err != nil {
		return
	}
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	state["result/"+id] = string(data)
	state["result-at/"+id] = e.Sys.Now().UTC().Format(time.RFC3339)
	_ = e.Sys.State.Save(state)
}
