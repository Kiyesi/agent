// Package keys reads who can sign in to this server with an SSH key, for
// the service's access map, and removes a key when a person asks at the
// server. It reads each login account's authorized_keys, and keeps only a
// key's fingerprint, its type, its comment and when the file last changed:
// never the key itself.
package keys

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxKeys caps what is read and sent, far above a usual server's.
const MaxKeys = 500

// readCap is the most read of one authorized_keys file.
const readCap = 256 << 10

// Files are where OpenSSH looks for a user's keys by default.
var Files = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

// Key is one line of a user's authorized_keys.
type Key struct {
	User        string `json:"user"`
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Comment     string `json:"comment,omitempty"`
	// ChangedAt is when the file it is in last changed: the newest a key
	// in it can be.
	ChangedAt time.Time `json:"changed_at"`
	// Restricted is set when the line has options, such as from= or
	// command=, that limit what the key may do.
	Restricted bool `json:"restricted,omitempty"`
	// Path is the file, for removing it; never sent.
	Path string `json:"-"`
}

// Account is a login account from /etc/passwd.
type Account struct {
	Name     string
	UID, GID int
	Home     string
}

// keyTypes are the key types OpenSSH accepts in authorized_keys.
var keyTypes = map[string]bool{
	"ssh-ed25519": true, "ssh-rsa": true, "ssh-dss": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
	"ssh-ed25519-cert-v01@openssh.com": true, "ssh-rsa-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
}

// Accounts are the accounts that can sign in: root, and every account with
// a real shell and a home folder.
func Accounts(fsys fs.FS) []Account {
	data, err := fs.ReadFile(fsys, "etc/passwd")
	if err != nil {
		return nil
	}
	var out []Account
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || !strings.HasPrefix(f[5], "/") || f[5] == "/" {
			continue
		}
		shell := path.Base(f[6])
		if f[0] != "root" && (f[6] == "" || shell == "nologin" || shell == "false" || shell == "sync" || shell == "halt" || shell == "shutdown") {
			continue
		}
		out = append(out, Account{Name: f[0], UID: uid, GID: gid, Home: path.Clean(f[5])})
	}
	return out
}

// Read returns every key that opens this server, by account. Files that
// are links, not plain files, or too big are left out.
func Read(fsys fs.FS) []Key {
	var out []Key
	seen := map[string]bool{}
	for _, a := range Accounts(fsys) {
		for _, f := range Files {
			p := path.Join(a.Home, f)
			if seen[p] {
				continue
			}
			seen[p] = true
			data, info, err := readPlain(fsys, strings.TrimPrefix(p, "/"))
			if err != nil {
				continue
			}
			for _, l := range Parse(data) {
				if len(out) >= MaxKeys {
					return out
				}
				l.User, l.ChangedAt, l.Path = a.Name, info.ModTime().UTC().Truncate(time.Second), p
				out = append(out, l)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// noFollowFS can open a file without following a link at its last step.
type noFollowFS interface {
	OpenNoFollow(name string) (fs.File, error)
}

var errNotPlain = errors.New("not a plain file")

func readPlain(fsys fs.FS, name string) ([]byte, fs.FileInfo, error) {
	var f fs.File
	var err error
	if nf, ok := fsys.(noFollowFS); ok {
		f, err = nf.OpenNoFollow(name)
	} else {
		f, err = fsys.Open(name)
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > readCap {
		return nil, nil, errNotPlain
	}
	data, err := io.ReadAll(io.LimitReader(f, readCap))
	return data, info, err
}

// Parse reads the keys in an authorized_keys file. A line may start with
// options; the key type is the first word OpenSSH knows.
func Parse(data []byte) []Key {
	var out []Key
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), readCap)
	for sc.Scan() {
		if k, ok := ParseLine(sc.Text()); ok {
			out = append(out, k)
		}
	}
	return out
}

// ParseLine reads one line, or says it holds no key.
func ParseLine(line string) (Key, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Key{}, false
	}
	fields := splitOptions(line)
	for i, w := range fields {
		if !keyTypes[w] || i+1 >= len(fields) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[i+1])
		if err != nil || len(blob) == 0 {
			return Key{}, false
		}
		return Key{
			Type:        w,
			Fingerprint: Fingerprint(blob),
			Comment:     clean(strings.Join(fields[i+2:], " ")),
			Restricted:  i > 0,
		}, true
	}
	return Key{}, false
}

// splitOptions splits a line on spaces, keeping quoted option values,
// such as command="echo hi", whole.
func splitOptions(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Fingerprint is the key's SHA256 fingerprint as ssh-keygen -l prints it.
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ValidFingerprint is a fingerprint as Fingerprint makes them.
func ValidFingerprint(s string) bool {
	rest, ok := strings.CutPrefix(s, "SHA256:")
	if !ok || len(rest) != 43 {
		return false
	}
	_, err := base64.RawStdEncoding.DecodeString(rest)
	return err == nil
}

// clean keeps a comment printable and short: it is typed by whoever made
// the key, such as ada@laptop.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 100 {
			break
		}
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// Print is a short hash of the keys, so the agent sends them again only
// when they change.
func Print(ks []Key) string {
	data, _ := json.Marshal(ks)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
