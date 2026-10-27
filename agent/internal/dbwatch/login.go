package dbwatch

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// How the agent signs in to a database. A password is never kept in plain
// text: one in the database's address is refused.
const (
	// LoginSocket: no password, the database trusts the server's own user
	// over its socket (PostgreSQL peer, MySQL auth_socket).
	LoginSocket = "socket"
	// LoginEncrypted: a password kept encrypted on this server, read only
	// into the agent's memory.
	LoginEncrypted = "encrypted"
	// LoginNone: the database asks for no password at all (a Redis or
	// MongoDB on this server without sign-in turned on).
	LoginNone = "none"
)

// CredentialPrefix names a database's encrypted password for systemd:
// /etc/credstore.encrypted/kiyesi.db.<name>, imported by the agent's unit.
const CredentialPrefix = "kiyesi.db."

// Where Kiyesi's own encrypted passwords and their key are kept, where
// systemd is older than 254: the password under /etc/kiyesi, the key under
// /var/lib/kiyesi, so a copy of either folder alone opens nothing. Tests
// change them.
var (
	OwnCredentialsDir = "/etc/kiyesi/credentials" // #nosec G101 -- a folder's path, not a credential
	KeyPath           = "/var/lib/kiyesi/db.key"
	// CredstoreDir is where systemd-creds keeps encrypted credentials.
	CredstoreDir = "/etc/credstore.encrypted" // #nosec G101 -- systemd's folder's path, not a credential
	// systemdCreds runs systemd-creds decrypt. Tests replace it.
	systemdCreds = func(ctx context.Context, args ...string) ([]byte, error) {
		path, err := exec.LookPath("systemd-creds")
		if err != nil {
			return nil, err
		}
		return exec.CommandContext(ctx, path, args...).Output() // #nosec G204 -- systemd's own tool, fixed arguments and a checked name
	}
)

// ErrPasswordInAddress is a password written in a database's address.
var ErrPasswordInAddress = errors.New("a password is written in its address. Kiyesi never keeps a database password in plain text: remove it, and run sudo kiyesi databases setup for a safe way to sign in")

// Secret is how the agent signs in to one database: the password, held
// only in memory, and the kind of login. It never leaves this server.
type Secret struct {
	Password string
	Kind     string
}

// LoginFor finds how to sign in to a database, from its settings. The
// password setting names where the password is kept, never the password:
// "credential" is the one encrypted for this database on this server.
func LoginFor(ctx context.Context, c Config, u *url.URL) (Secret, error) {
	if _, ok := u.User.Password(); ok {
		return Secret{}, ErrPasswordInAddress
	}
	switch c.Password {
	case "":
		if socketAddress(u) {
			return Secret{Kind: LoginSocket}, nil
		}
		return Secret{Kind: LoginNone}, nil
	case "credential":
		pw, err := credential(ctx, c.Name)
		if err != nil {
			return Secret{}, err
		}
		return Secret{Password: pw, Kind: LoginEncrypted}, nil
	}
	// Never repeated back: someone may have typed the password itself here.
	return Secret{}, errors.New("its password setting is not one Kiyesi knows. It names where the password is kept, never the password: use password: credential for one encrypted on this server")
}

// socketAddress says whether the address reaches the database through its
// socket file, where it can trust the server's own user.
func socketAddress(u *url.URL) bool {
	q := u.Query()
	return strings.HasPrefix(q.Get("host"), "/") || strings.HasPrefix(q.Get("socket"), "/")
}

// credential reads a database's encrypted password, in this order: as
// systemd hands it to the running agent; with systemd-creds, for a command
// run by hand; and Kiyesi's own encrypted file, on older systemd.
func credential(ctx context.Context, name string) (string, error) {
	cred := CredentialPrefix + name
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, cred)); err == nil { // #nosec G304 G703 -- systemd's folder for this service, and a name checked by NamePattern
			return strings.TrimRight(string(b), "\r\n"), nil
		}
	}
	stored := filepath.Join(CredstoreDir, cred)
	if _, err := os.Stat(stored); err == nil {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		b, err := systemdCreds(ctx, "decrypt", "--name="+cred, stored, "-")
		if err != nil {
			return "", fmt.Errorf("its encrypted password in %s could not be read with systemd-creds (run this as root)", stored)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	own := filepath.Join(OwnCredentialsDir, name+".enc")
	b, err := os.ReadFile(own) // #nosec G304 -- a fixed folder and a checked name
	if err != nil {
		return "", fmt.Errorf("it has no encrypted password: none in %s or %s. Run sudo kiyesi databases setup for the steps", stored, own)
	}
	return Decrypt(name, strings.TrimSpace(string(b)))
}

const sealedPrefix = "kiyesi-enc-v1:"

// key reads the key for Kiyesi's own encrypted passwords, making it the
// first time, readable by root only.
func key(create bool) ([]byte, error) {
	b, err := os.ReadFile(KeyPath)
	if err == nil && len(b) == 32 {
		return b, nil
	}
	if !create {
		return nil, fmt.Errorf("its key, %s, is missing: encrypt the password again on this server", KeyPath)
	}
	if err := os.MkdirAll(filepath.Dir(KeyPath), 0o700); err != nil {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(KeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		// Made by another command meanwhile: use that one.
		if errors.Is(err, os.ErrExist) {
			return key(false)
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Encrypt seals a database's password with AES-256-GCM, bound to the
// database's name, for Kiyesi's own encrypted file. It makes the key on
// first use.
func Encrypt(name, password string) (string, error) {
	k, err := key(true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(password), []byte(CredentialPrefix+name))
	return sealedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens what Encrypt sealed for this database.
func Decrypt(name, text string) (string, error) {
	raw, ok := strings.CutPrefix(text, sealedPrefix)
	if !ok {
		return "", errors.New("its encrypted password is not one Kiyesi wrote: make it again with sudo kiyesi databases encrypt")
	}
	sealed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", errors.New("its encrypted password is damaged: make it again with sudo kiyesi databases encrypt")
	}
	k, err := key(false)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", errors.New("its encrypted password is damaged: make it again with sudo kiyesi databases encrypt")
	}
	pw, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(CredentialPrefix+name))
	if err != nil {
		return "", errors.New("its encrypted password does not open with this server's key, or was made for another database: make it again with sudo kiyesi databases encrypt")
	}
	return string(pw), nil
}
