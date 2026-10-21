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
	"syscall"

	"github.com/kiyesi/kiyesi/agent/internal/system"
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
	// ChmodFile changes the mode of the plain file at path, never through a
	// link, and only while it is still the file want names. The check and
	// the change are made on one open file, so nothing can be swapped in
	// between them.
	ChmodFile(path string, want FileID, perm fs.FileMode) error
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
// sees half a file. The temporary file gets a random name, made only if no
// file has it, so nobody can place a link where Kiyesi writes first.
func (RealHost) WriteFile(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- system folders such as /etc/ssh/sshd_config.d
		return err
	}
	tmp, err := os.CreateTemp(dir, ".kiyesi-*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	done = true
	return nil
}

func (RealHost) Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ChmodFile opens path without following a link and without waiting on a
// pipe or a device, checks it is a plain file and still the one want names,
// and changes the mode of that open file.
func (RealHost) ChmodFile(path string, want FileID, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- a finding's own file, checked below before anything changes
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("%s is a link now, so it is left alone", path)
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file now, so it is left alone", path)
	}
	if id, ok := IDOf(info); !ok || id != want {
		return fmt.Errorf("%s is no longer the file Kiyesi looked at (it was replaced or moved), so it is left alone", path)
	}
	return f.Chmod(perm)
}

func (RealHost) Has(name string) bool {
	if !allowed[name] {
		return false
	}
	_, err := system.Find(name)
	return err == nil
}

// Run runs name with args. apt and its helpers are told nobody is there to
// answer questions, and to keep the server's own settings files.
func (RealHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !allowed[name] {
		return nil, fmt.Errorf("%s is not on the fixes' list of programs", name)
	}
	path, err := system.Find(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed in %s", name, strings.Join(system.ProgramDirs, ", "))
	}
	// #nosec G204 -- name is checked against the list above and taken from root's own folders; args are fixed by each fix.
	cmd := exec.CommandContext(ctx, path, args...)
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
