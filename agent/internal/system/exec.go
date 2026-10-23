package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// allowed lists every program the scan may run. All of them only read:
// apt-get runs with -s (simulate), systemctl with is-active, and so on.
var allowed = map[string]bool{
	"apt-get":    true,
	"journalctl": true,
	"systemctl":  true,
	"ufw":        true,
	"nft":        true,
	"iptables":   true,
	"sshd":       true,
	"trivy":      true,
	"gitleaks":   true,
	// rpm -qa only lists installed packages, and rpm -Va only compares
	// them with the package database (Red Hat family).
	"rpm": true,
	// dpkg --verify only compares installed files with the package
	// database's checksums (Debian family).
	"dpkg": true,
}

// ExecRunner runs allowlisted commands on this machine.
type ExecRunner struct{}

// Has reports whether name is allowed and installed.
func (ExecRunner) Has(name string) bool {
	if !allowed[name] {
		return false
	}
	_, err := Find(name)
	return err == nil
}

// Run runs name with args and returns its standard output. Standard error
// is included in the returned error, shortened, so a check can say why.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !allowed[name] {
		return nil, fmt.Errorf("%s is not on the scan's list of read-only programs", name)
	}
	path, err := Find(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed in %s", name, strings.Join(ProgramDirs, ", "))
	}
	// #nosec G204 -- name is checked against the read-only allowlist above and
	// taken from root's own folders, and args are fixed by each check.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "SYSTEMD_PAGER=", "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.Bytes(), &CommandError{Name: name, Code: exitErr.ExitCode(), Stderr: msg}
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

// CommandError is a command that ran and exited with an error.
type CommandError struct {
	Name   string
	Code   int
	Stderr string
}

func (e *CommandError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("%s exited with code %d", e.Name, e.Code)
	}
	return fmt.Sprintf("%s exited with code %d: %s", e.Name, e.Code, e.Stderr)
}
