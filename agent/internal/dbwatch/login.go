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

	"github.com/kiyesi/kiyesi/agent/internal/cloudlogin"
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
	// LoginIAM: a short-lived token from the server's own cloud identity
	// (AWS IAM, Google Cloud, Azure managed identity), or MongoDB's AWS and
	// workload identity sign-in. Nothing secret is stored.
	LoginIAM = "iam"
	// LoginCertificate: an X.509 certificate kept on the server, root only.
	LoginCertificate = "certificate"
	// LoginVault: a password, or a short-lived user, from HashiCorp Vault.
	LoginVault = "vault"
	// LoginAWSSecret: a password from AWS Secrets Manager, read with the
	// server's AWS role.
	LoginAWSSecret = "aws-secret"
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
// only in memory, the user when it is not the address's own (a user Vault
// made), and the kind of login. It never leaves this server.
type Secret struct {
	Password string
	User     string
	Kind     string
}

// LoginFor finds how to sign in to a database, from its settings. The
// password setting names where the password is kept, never the password:
//
//	credential             encrypted for this database on this server
//	aws-iam                an RDS or Aurora IAM token from the server's AWS role
//	gcp-iam                a Cloud SQL token from the VM's service account
//	azure-identity[:id]    a token from the VM's managed identity
//	aws-secret:<arn>       a password in AWS Secrets Manager
//	vault:<path>[#field]   a password, or a short-lived user, from Vault
//
// MongoDB's own certificate, AWS and workload identity sign-ins are named
// in its address (authMechanism=), with no password setting.
func LoginFor(ctx context.Context, c Config, u *url.URL) (Secret, error) {
	if _, ok := u.User.Password(); ok {
		return Secret{}, ErrPasswordInAddress
	}
	kind, arg, _ := strings.Cut(c.Password, ":")
	switch kind {
	case "":
		return addressLogin(u)
	case "credential":
		pw, err := credential(ctx, c.Name)
		if err != nil {
			return Secret{}, err
		}
		return Secret{Password: pw, Kind: LoginEncrypted}, nil
	case "aws-iam", "gcp-iam", "azure-identity":
		if err := needsTLS(u); err != nil {
			return Secret{}, err
		}
		tok, err := cloudToken(ctx, kind, arg, u)
		if err != nil {
			return Secret{}, err
		}
		return Secret{Password: tok, Kind: LoginIAM}, nil
	case "aws-secret":
		if arg == "" {
			return Secret{}, errors.New("name the secret: password: aws-secret:<its ARN>")
		}
		if err := needsTLS(u); err != nil && !local(u.Hostname()) {
			return Secret{}, err
		}
		keys, err := cloudlogin.AWSCredentialsFor(ctx)
		if err != nil {
			return Secret{}, err
		}
		region := cloudlogin.RDSRegion(u.Hostname())
		if region == "" {
			region = cloudlogin.AWSRegion(ctx)
		}
		pw, err := cloudlogin.AWSSecret(ctx, keys, arg, region)
		if err != nil {
			return Secret{}, err
		}
		return Secret{Password: pw, Kind: LoginAWSSecret}, nil
	case "vault":
		if arg == "" {
			return Secret{}, errors.New("name the secret: password: vault:<its path>, such as vault:database/creds/kiyesi-ro")
		}
		if err := needsTLS(u); err != nil && !local(u.Hostname()) {
			return Secret{}, err
		}
		if c.Vault == nil {
			return Secret{}, errors.New("no Vault is set: add its address under vault: in /etc/kiyesi/config.yaml")
		}
		l, err := c.Vault.Read(ctx, arg)
		if err != nil {
			return Secret{}, err
		}
		return Secret{Password: l.Password, User: l.Username, Kind: LoginVault}, nil
	}
	// Never repeated back: someone may have typed the password itself here.
	return Secret{}, errors.New("its password setting is not one Kiyesi knows. It names where the password is kept, never the password: credential, aws-iam, gcp-iam, azure-identity, aws-secret:<ARN> or vault:<path>")
}

// addressLogin is the login an address gives by itself: MongoDB's
// certificate, AWS or workload identity sign-in, the socket, or none.
func addressLogin(u *url.URL) (Secret, error) {
	q := u.Query()
	switch strings.ToUpper(q.Get("authMechanism")) {
	case "MONGODB-X509":
		file := q.Get("tlsCertificateKeyFile")
		if file == "" {
			return Secret{}, errors.New("a certificate sign-in needs its file: add &tlsCertificateKeyFile=/etc/kiyesi/credentials/<name>.pem")
		}
		info, err := os.Stat(file) // #nosec G304 G703 -- a path from root's own settings file
		if err != nil {
			return Secret{}, fmt.Errorf("its certificate file %s could not be read", file)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return Secret{}, fmt.Errorf("its certificate file %s may be read by other users: sudo chmod 600 %s", file, file)
		}
		return Secret{Kind: LoginCertificate}, nil
	case "MONGODB-AWS", "MONGODB-OIDC":
		return Secret{Kind: LoginIAM}, nil
	}
	if socketAddress(u) {
		return Secret{Kind: LoginSocket}, nil
	}
	return Secret{Kind: LoginNone}, nil
}

// needsTLS refuses a cloud login over a connection whose certificate is not
// checked: the token or password would otherwise cross the network open.
func needsTLS(u *url.URL) error {
	q := u.Query()
	switch engineOf(u) {
	case "postgresql":
		if m := q.Get("sslmode"); m == "verify-full" || m == "verify-ca" {
			return nil
		}
		return errors.New("its address must check the database's certificate: add ?sslmode=verify-full (with &sslrootcert= for the provider's authority)")
	case "mysql":
		if q.Get("tls") == "true" {
			return nil
		}
		return errors.New("its address must use TLS: add ?tls=true (with &ca= for the provider's authority)")
	case "redis":
		if u.Scheme == "rediss" {
			return nil
		}
		return errors.New("its address must use TLS: start it with rediss://")
	case "mongodb":
		if u.Scheme == "mongodb+srv" || q.Get("tls") == "true" || q.Get("ssl") == "true" {
			return nil
		}
		return errors.New("its address must use TLS: add tls=true")
	}
	return nil
}

// cloudToken makes the token a cloud database takes as its password.
func cloudToken(ctx context.Context, kind, arg string, u *url.URL) (string, error) {
	switch kind {
	case "aws-iam":
		e := engineOf(u)
		if e != "postgresql" && e != "mysql" {
			return "", errors.New("AWS IAM sign-in is for RDS and Aurora PostgreSQL and MySQL")
		}
		region := cloudlogin.RDSRegion(u.Hostname())
		if region == "" {
			return "", errors.New("AWS IAM sign-in needs the database's RDS address (….rds.amazonaws.com), which names its region")
		}
		keys, err := cloudlogin.AWSCredentialsFor(ctx)
		if err != nil {
			return "", err
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"postgresql": "5432", "mysql": "3306"}[e]
		}
		return cloudlogin.RDSToken(keys, u.Hostname(), port, u.User.Username(), region), nil
	case "gcp-iam":
		return cloudlogin.GCPToken(ctx)
	default:
		return cloudlogin.AzureToken(ctx, "", arg)
	}
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
