package fix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Host is how a fix reads and changes the server. Paths are absolute.
// Tests hand the fixes a fake one.
type Host interface {
	ReadFile(path string) ([]byte, error)
	// Lstat does not follow a symbolic link, so a fix never changes the
	// file a link points to by mistake.
	Lstat(path string) (fs.FileInfo, error)
	WriteFile(path string, data []byte, perm fs.FileMode) error
	Remove(path string) error
	Chmod(path string, perm fs.FileMode) error
	// Run runs a program from the fixes' own short list.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	Has(name string) bool
}

// allowed lists every program a fix may run. It is kept apart from the
// scan's read-only list on purpose: the scan cannot run any of these.
var allowed = map[string]bool{
	"systemctl": true, // reload ssh, start fail2ban
	"sshd":      true, // sshd -t checks a setting before SSH reloads it; sshd -T reads it back
	"ufw":       true,
	"apt-get":   true,
	"certbot":   true,
	"docker":    true, // docker image prune and docker builder prune, never a container or volume
}

// RealHost changes this machine.
type RealHost struct{}

func (RealHost) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } // #nosec G304 -- paths are fixed by each fix, or a finding's own file

func (RealHost) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }

// WriteFile writes through a temporary file and a rename, so a reader never
// sees half a file.
func (RealHost) WriteFile(path string, data []byte, perm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- system folders such as /etc/ssh/sshd_config.d
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), ".kiyesi-"+filepath.Base(path))
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (RealHost) Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (RealHost) Chmod(path string, perm fs.FileMode) error { return os.Chmod(path, perm) }

func (RealHost) Has(name string) bool {
	if !allowed[name] {
		return false
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// Run runs name with args. apt and its helpers are told nobody is there to
// answer questions, and to keep the server's own settings files.
func (RealHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !allowed[name] {
		return nil, fmt.Errorf("%s is not on the fixes' list of programs", name)
	}
	// #nosec G204 -- name is checked against the list above; args are fixed by each fix.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "SYSTEMD_PAGER=", "NO_COLOR=1",
		"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_SUSPEND=1", "APT_LISTCHANGES_FRONTEND=none")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if len(msg) > 400 {
			msg = "…" + msg[len(msg)-400:]
		}
		if msg != "" {
			return out.Bytes(), fmt.Errorf("%s %s failed: %s", name, strings.Join(args, " "), msg)
		}
		return out.Bytes(), fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return out.Bytes(), nil
}
