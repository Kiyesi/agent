package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type certificatesCheck struct{}

func (certificatesCheck) ID() string { return "certificates" }

type certFile struct {
	path   string // without the leading slash
	source string // certbot, caddy or other
}

// caddyGlobs are where Caddy keeps certificates: as a system service, as a
// user, and in a Docker volume.
var caddyGlobs = []string{
	"var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt",
	"root/.local/share/caddy/certificates/*/*/*.crt",
	"home/*/.local/share/caddy/certificates/*/*/*.crt",
	"var/lib/docker/volumes/*/_data/caddy/certificates/*/*/*.crt",
	"var/lib/docker/volumes/*/_data/certificates/*/*/*.crt",
}

func (certificatesCheck) Run(_ context.Context, env *Env) Result {
	fsys := env.Sys.FS
	var files []certFile
	blocked := false

	// Let's Encrypt keeps live certificates in a folder only root can read.
	live, err := fs.ReadDir(fsys, "etc/letsencrypt/live")
	switch {
	case err == nil:
		for _, d := range live {
			if d.IsDir() {
				files = append(files, certFile{path: path.Join("etc/letsencrypt/live", d.Name(), "cert.pem"), source: "certbot"})
			}
		}
	case errors.Is(err, fs.ErrPermission):
		blocked = true
	}
	for _, g := range caddyGlobs {
		matches, _ := fs.Glob(fsys, g)
		for _, m := range matches {
			files = append(files, certFile{path: m, source: "caddy"})
		}
	}
	for _, p := range webServerCertPaths(fsys) {
		files = append(files, certFile{path: p, source: "other"})
	}
	if _, err := fs.Stat(fsys, "var/lib/docker/volumes"); errors.Is(err, fs.ErrPermission) {
		blocked = true
	}

	now := env.Sys.Now()
	limit := env.Cfg.Limits.CertificateDays
	type seenKey struct{ host, path string }
	seen := map[seenKey]bool{}
	var found []Finding
	count := 0
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f.path)
		if errors.Is(err, fs.ErrPermission) {
			blocked = true
			continue
		}
		if err != nil {
			continue
		}
		cert := firstCert(data)
		if cert == nil {
			continue
		}
		host := certHost(cert)
		k := seenKey{host, f.path}
		if seen[k] {
			continue
		}
		seen[k] = true
		count++
		left := cert.NotAfter.Sub(now)
		vars := map[string]string{"host": host, "path": "/" + f.path}
		variant := ""
		if f.source != "certbot" {
			variant = f.source
		}
		switch {
		case left <= 0:
			vars["days"] = strconv.Itoa(int(-left.Hours()) / 24)
			found = append(found, Finding{Key: "expired", Variant: variant, Vars: vars})
		case left < time.Duration(limit)*24*time.Hour:
			vars["days"] = strconv.Itoa(int(left.Hours()) / 24)
			found = append(found, Finding{Key: "expiring", Variant: variant, Vars: vars})
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Key == "expired" && found[j].Key != "expired" })
	if len(found) > 0 {
		return Fail(found...)
	}
	// A folder we could not read may hold an expiring certificate.
	if blocked && !env.Sys.Root {
		return NeedsRoot()
	}
	if count == 0 {
		return PassNone()
	}
	return Pass(map[string]string{"count": strconv.Itoa(count), "limit": strconv.Itoa(limit)})
}

func firstCert(data []byte) *x509.Certificate {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return c
			}
		}
	}
}

func certHost(c *x509.Certificate) string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return "an unnamed site"
}

// webServerCertPaths reads the certificate files named in nginx and Apache settings.
func webServerCertPaths(fsys fs.FS) []string {
	var out []string
	seen := map[string]bool{}
	for _, g := range []string{
		"etc/nginx/nginx.conf", "etc/nginx/conf.d/*.conf", "etc/nginx/sites-enabled/*",
		"etc/apache2/sites-enabled/*", "etc/httpd/conf.d/*.conf",
	} {
		matches, _ := fs.Glob(fsys, g)
		for _, m := range matches {
			data, err := fs.ReadFile(fsys, m)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(bytes.NewReader(data))
			for sc.Scan() {
				f := strings.Fields(strings.TrimSpace(sc.Text()))
				if len(f) < 2 || (f[0] != "ssl_certificate" && f[0] != "SSLCertificateFile") {
					continue
				}
				p := strings.TrimPrefix(strings.Trim(strings.TrimSuffix(f[1], ";"), `"'`), "/")
				if p != "" && !strings.Contains(p, "$") && !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	return out
}
