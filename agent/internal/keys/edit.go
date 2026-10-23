package keys

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Removal is one file a key is to be taken out of, with its exact lines.
type Removal struct {
	Account Account
	Path    string
	Lines   []string
}

// Plan finds every line that holds the key, file by file.
func Plan(fsys fs.FS, fingerprint string) []Removal {
	var out []Removal
	seen := map[string]bool{}
	for _, a := range Accounts(fsys) {
		for _, f := range Files {
			p := filepath.Join(a.Home, f)
			if seen[p] {
				continue
			}
			seen[p] = true
			data, _, err := readPlain(fsys, strings.TrimPrefix(p, "/"))
			if err != nil {
				continue
			}
			var lines []string
			for _, line := range strings.Split(string(data), "\n") {
				if k, ok := ParseLine(line); ok && k.Fingerprint == fingerprint {
					lines = append(lines, line)
				}
			}
			if len(lines) > 0 {
				out = append(out, Removal{Account: a, Path: p, Lines: lines})
			}
		}
	}
	return out
}

// Edit takes the given lines out of data, every time each appears, and
// adds the others at the end. Nothing else in the file changes.
func Edit(data []byte, remove, add []string) []byte {
	drop := map[string]bool{}
	for _, l := range remove {
		drop[strings.TrimRight(l, "\r")] = true
	}
	var b bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), readCap)
	have := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if drop[strings.TrimRight(line, "\r")] {
			continue
		}
		have[line] = true
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, l := range add {
		if !have[l] {
			have[l] = true
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// Writer changes one account's authorized_keys file.
type Writer interface {
	Edit(ctx context.Context, a Account, path string, remove, add []string) error
}

// RealWriter changes the file with the account's own rights: root's in
// this process, anyone else's in a copy of kiyesi started as that person,
// so a link or a moved folder in their home can never reach a file only
// root may change.
type RealWriter struct{}

// Edit changes one file, as its account.
func (RealWriter) Edit(ctx context.Context, a Account, path string, remove, add []string) error {
	if a.UID == 0 {
		return EditOwn(path, remove, add)
	}
	if a.UID < 0 || a.GID < 0 || a.UID > 1<<31 || a.GID > 1<<31 {
		return fmt.Errorf("%s has an account number Kiyesi cannot use", a.Name)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := json.Marshal(editRequest{Path: path, Remove: remove, Add: add})
	if err != nil {
		return err
	}
	// #nosec G204 -- kiyesi itself, with a fixed hidden command; the file and lines go on standard input.
	cmd := exec.CommandContext(ctx, self, "keys", "edit-own")
	cmd.Stdin = bytes.NewReader(in)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(a.UID), Gid: uint32(a.GID), Groups: []uint32{}, // #nosec G115 -- checked above
	}}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s: %s", path, msg)
	}
	return nil
}

type editRequest struct {
	Path   string   `json:"path"`
	Remove []string `json:"remove"`
	Add    []string `json:"add"`
}

// EditOwnFrom runs the hidden kiyesi keys edit-own: it reads what to change
// from in, as the account that owns the file. It refuses to run as root,
// which never needs it.
func EditOwnFrom(in io.Reader) error {
	if os.Geteuid() == 0 {
		return errors.New("this runs only as the file's own account")
	}
	var req editRequest
	if err := json.NewDecoder(io.LimitReader(in, readCap*2)).Decode(&req); err != nil {
		return fmt.Errorf("bad request: %w", err)
	}
	return EditOwn(req.Path, req.Remove, req.Add)
}

// EditOwn changes an authorized_keys file the running account owns. The
// file must be a plain file, never a link, owned by this account, in a
// folder only this account (or root) can write. The new file is written
// beside it and moved into place, so sshd never reads half of it.
func EditOwn(path string, remove, add []string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "authorized_keys" && filepath.Base(path) != "authorized_keys2" {
		return fmt.Errorf("%s is not an authorized_keys file", path)
	}
	me := os.Geteuid()
	dir := filepath.Dir(path)
	if err := safeDir(dir, me); err != nil {
		return err
	}
	if me == 0 {
		// Root follows no folder another account could swap for a link.
		for d := filepath.Dir(dir); ; d = filepath.Dir(d) {
			if err := safeDir(d, 0); err != nil {
				return err
			}
			if d == "/" {
				break
			}
		}
	}
	var data []byte
	mode := fs.FileMode(0o600)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) // #nosec G304 -- an authorized_keys file, checked below
	switch {
	case errors.Is(err, fs.ErrNotExist) && len(remove) == 0:
		// Putting a key back into a file deleted since: made anew.
	case errors.Is(err, syscall.ELOOP):
		return fmt.Errorf("%s is a link, so it is left alone", path)
	case err != nil:
		return err
	default:
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		switch {
		case !info.Mode().IsRegular():
			_ = f.Close()
			return fmt.Errorf("%s is not a plain file, so it is left alone", path)
		case !ok || int(st.Uid) != me || st.Nlink != 1:
			_ = f.Close()
			return fmt.Errorf("%s does not belong to this account alone, so it is left alone", path)
		case info.Size() > readCap:
			_ = f.Close()
			return fmt.Errorf("%s is too big to change safely", path)
		}
		mode = info.Mode().Perm()
		data, err = io.ReadAll(io.LimitReader(f, readCap))
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	next := Edit(data, remove, add)
	if bytes.Equal(next, data) {
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".authorized_keys-kiyesi-*")
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
	if err := tmp.Chmod(mode &^ 0o022); err != nil {
		return err
	}
	if _, err := tmp.Write(next); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
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

// safeDir checks a folder is a real folder, owned by this account or root,
// that nobody else can write to.
func safeDir(dir string, me int) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir():
		return fmt.Errorf("%s is not a folder, so nothing in it is changed", dir)
	case !ok || (int(st.Uid) != me && st.Uid != 0):
		return fmt.Errorf("%s belongs to another account, so nothing in it is changed", dir)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("others can write to %s, so nothing in it is changed", dir)
	}
	return nil
}
