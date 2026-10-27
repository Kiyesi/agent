package cloudlogin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultSettings say where the company's HashiCorp Vault is and how the
// server signs in to it. They name no secret: the server proves who it is
// with its cloud identity, or with an AppRole whose secret ID is kept
// encrypted on the server.
type VaultSettings struct {
	// Address is Vault's address, such as https://vault.example.com:8200.
	Address string `yaml:"address"`
	// CA is the file of the authority that signed Vault's certificate, when
	// it is not one the system trusts.
	CA string `yaml:"ca"`
	// Auth is how the server signs in: aws, gcp, azure or approle.
	Auth string `yaml:"auth"`
	// Role is Vault's role for this server (for approle, its role ID).
	Role string `yaml:"role"`
	// Mount is where the sign-in method is mounted, when not at its usual path.
	Mount string `yaml:"mount"`
	// ServerID is the X-Vault-AWS-IAM-Server-ID Vault asks for, if any.
	ServerID string `yaml:"server_id"`
	// Namespace is the Vault Enterprise namespace, if any.
	Namespace string `yaml:"namespace"`
}

// VaultLogin is what a database's password: vault:… setting gives: a
// username when Vault made the user (its database engine), and the password.
type VaultLogin struct {
	Username, Password string
	// Short says the user is one Vault made for a short time.
	Short bool
}

// Vault signs in once and keeps the token, and each secret, in memory for
// as long as Vault allows; a short-lived database user is renewed before
// its lease ends, and a new one read when it cannot be.
type Vault struct {
	S VaultSettings
	// SecretID reads the AppRole's secret ID, kept encrypted on the server.
	SecretID func(ctx context.Context) (string, error)

	mu       sync.Mutex
	token    string
	tokenEnd time.Time
	cache    map[string]cached
	http     *http.Client
}

type cached struct {
	login   VaultLogin
	leaseID string
	renewAt time.Time
	end     time.Time
}

// kvRefresh is how often a static secret is read again, so a password
// changed in Vault is picked up.
const kvRefresh = 5 * time.Minute

// Read gives the login a path names: database/creds/<role> for a user
// Vault makes, or a key-value secret, with #field naming the field
// (password when not given).
func (v *Vault) Read(ctx context.Context, path string) (VaultLogin, error) {
	if v.S.Address == "" {
		return VaultLogin{}, errors.New("no Vault is set: add its address under vault: in /etc/kiyesi/config.yaml")
	}
	if u, err := url.Parse(v.S.Address); err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return VaultLogin{}, errors.New("the address of your Vault must start with https://, so its token and passwords never cross the network in clear text")
	}
	field := "password"
	if p, f, ok := strings.Cut(path, "#"); ok {
		path, field = p, f
	}
	path = strings.Trim(path, "/")
	v.mu.Lock()
	defer v.mu.Unlock()
	now := clock()
	if c, ok := v.cache[path+"#"+field]; ok && now.Before(c.end) {
		if now.Before(c.renewAt) {
			return c.login, nil
		}
		// A short-lived user: ask Vault for more time on the same one. When
		// its longest time is reached, Vault gives no later end: a new user.
		if c.leaseID != "" {
			if left, err := v.renew(ctx, c.leaseID); err == nil && now.Add(left).After(c.end) {
				c.renewAt, c.end = now.Add(left*2/3), now.Add(left)
				v.cache[path+"#"+field] = c
				return c.login, nil
			}
		}
	}
	var out struct {
		LeaseID       string         `json:"lease_id"`
		LeaseDuration int            `json:"lease_duration"`
		Data          map[string]any `json:"data"`
	}
	if err := v.call(ctx, http.MethodGet, "/v1/"+path, nil, &out); err != nil {
		return VaultLogin{}, err
	}
	login := VaultLogin{}
	data := out.Data
	// A key-value secret of version 2 keeps its fields one level down.
	if inner, ok := data["data"].(map[string]any); ok {
		if _, meta := data["metadata"]; meta {
			data = inner
		}
	}
	if u, ok := data["username"].(string); ok && out.LeaseID != "" {
		login.Username, login.Short = u, true
	}
	pw, _ := data[field].(string)
	if pw == "" {
		return VaultLogin{}, fmt.Errorf("the secret %s in Vault has no %s field", path, field)
	}
	login.Password = pw
	c := cached{login: login, leaseID: out.LeaseID}
	if out.LeaseDuration > 0 && out.LeaseID != "" {
		left := time.Duration(out.LeaseDuration) * time.Second
		c.renewAt, c.end = now.Add(left*2/3), now.Add(left)
	} else {
		c.renewAt, c.end = now.Add(kvRefresh), now.Add(kvRefresh)
	}
	if v.cache == nil {
		v.cache = map[string]cached{}
	}
	v.cache[path+"#"+field] = c
	return login, nil
}

// renew asks Vault for more time on a lease, and gives the time left.
func (v *Vault) renew(ctx context.Context, leaseID string) (time.Duration, error) {
	var out struct {
		LeaseDuration int `json:"lease_duration"`
	}
	if err := v.call(ctx, http.MethodPut, "/v1/sys/leases/renew", map[string]string{"lease_id": leaseID}, &out); err != nil {
		return 0, err
	}
	return time.Duration(out.LeaseDuration) * time.Second, nil
}

// call sends one request with the server's Vault token, signing in first
// when it has none or it ran out.
func (v *Vault) call(ctx context.Context, method, path string, body any, out any) error {
	if v.token == "" || !clock().Before(v.tokenEnd) {
		if err := v.login(ctx); err != nil {
			return err
		}
	}
	err := v.do(ctx, method, path, v.token, body, out)
	if h, ok := err.(*httpError); ok && h.status == http.StatusForbidden {
		// The token may have been revoked: sign in again, once.
		if err := v.login(ctx); err != nil {
			return err
		}
		err = v.do(ctx, method, path, v.token, body, out)
	}
	if h, ok := err.(*httpError); ok {
		switch h.status {
		case http.StatusForbidden:
			return fmt.Errorf("the Vault policy for this server does not allow %s", strings.TrimPrefix(path, "/v1/"))
		case http.StatusNotFound:
			return fmt.Errorf("Vault has nothing at %s", strings.TrimPrefix(path, "/v1/"))
		}
		return fmt.Errorf("Vault refused %s: %v", strings.TrimPrefix(path, "/v1/"), err)
	}
	return err
}

// login signs the server in to Vault with its cloud identity or AppRole.
func (v *Vault) login(ctx context.Context) error {
	method := v.S.Auth
	mount := v.S.Mount
	if mount == "" {
		mount = method
	}
	var body map[string]string
	switch method {
	case "aws":
		c, err := AWSCredentialsFor(ctx)
		if err != nil {
			return err
		}
		if body, err = VaultAWSLogin(c, v.S.Role, v.S.ServerID); err != nil {
			return err
		}
	case "gcp":
		jwt, err := GCPIdentityJWT(ctx, "vault/"+v.S.Role)
		if err != nil {
			return err
		}
		body = map[string]string{"role": v.S.Role, "jwt": jwt}
	case "azure":
		jwt, err := AzureToken(ctx, "https://management.azure.com/", "")
		if err != nil {
			return err
		}
		sub, group, name, err := AzureVM(ctx)
		if err != nil {
			return err
		}
		body = map[string]string{"role": v.S.Role, "jwt": jwt, "subscription_id": sub, "resource_group_name": group, "vm_name": name}
	case "approle":
		if v.SecretID == nil {
			return errors.New("the AppRole's secret ID is not set: encrypt it with sudo kiyesi databases encrypt vault")
		}
		secret, err := v.SecretID(ctx)
		if err != nil {
			return fmt.Errorf("the AppRole's secret ID: %v", err)
		}
		body = map[string]string{"role_id": v.S.Role, "secret_id": secret}
	default:
		return errors.New("vault auth must be aws, gcp, azure or approle")
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := v.do(ctx, http.MethodPost, "/v1/auth/"+strings.Trim(mount, "/")+"/login", "", body, &out); err != nil {
		if h, ok := err.(*httpError); ok && (h.status == http.StatusBadRequest || h.status == http.StatusForbidden) {
			return fmt.Errorf("Vault did not let this server sign in as the role %s (%s): check the role is bound to this server", v.S.Role, method)
		}
		return fmt.Errorf("Vault could not be reached at %s", v.S.Address)
	}
	if out.Auth.ClientToken == "" {
		return errors.New("Vault gave no token")
	}
	v.token = out.Auth.ClientToken
	left := time.Duration(out.Auth.LeaseDuration) * time.Second
	if left <= 0 {
		left = time.Hour
	}
	v.tokenEnd = clock().Add(left * 9 / 10)
	return nil
}

func (v *Vault) do(ctx context.Context, method, path, token string, body any, out any) error {
	if v.http == nil {
		hc, err := vaultHTTP(v.S.CA)
		if err != nil {
			return err
		}
		v.http = hc
	}
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(v.S.Address, "/")+path, rd)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if v.S.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.S.Namespace)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	b, err := read(resp)
	if err != nil {
		return err
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

// vaultHTTP checks Vault's certificate against the system's authorities,
// or the one in ca.
func vaultHTTP(ca string) (*http.Client, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, err := os.ReadFile(ca) // #nosec G304 -- a path from root's own settings file
		if err != nil {
			return nil, fmt.Errorf("the certificate authority for Vault, %s, could not be read", ca)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the certificate authority for Vault, %s, holds no certificate", ca)
		}
		t.RootCAs = pool
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: t, ResponseHeaderTimeout: 15 * time.Second,
	}}, nil
}

// loopback says whether a host is this machine, where plain http is safe.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
