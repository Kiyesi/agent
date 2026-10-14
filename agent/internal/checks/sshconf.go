package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// SSH is the SSH server's login settings.
type SSH struct {
	Present       bool
	PasswordLogin bool
	RootLogin     bool
}

func readSSH(ctx context.Context, sys *system.System) SSH {
	var settings map[string]string
	if sys.Root && sys.Exec.Has("sshd") {
		// sshd -T prints the settings in force, with every default filled in.
		if out, err := sys.Exec.Run(ctx, "sshd", "-T"); err == nil {
			settings = parseSSHDT(out)
		}
	}
	if settings == nil {
		var ok bool
		settings, ok = parseSSHDConfig(sys.FS)
		if !ok {
			return SSH{}
		}
	}
	return SSH{
		Present:       true,
		PasswordLogin: passwordLogin(settings),
		RootLogin:     rootLogin(sys.FS, settings["permitrootlogin"]),
	}
}

func value(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok {
		return strings.ToLower(v)
	}
	return def
}

// passwordLogin: passwords are accepted directly, or through
// keyboard-interactive sign-in when PAM is on.
func passwordLogin(m map[string]string) bool {
	if value(m, "passwordauthentication", "yes") != "no" {
		return true
	}
	kbd := value(m, "kbdinteractiveauthentication", value(m, "challengeresponseauthentication", "yes"))
	return kbd != "no" && value(m, "usepam", "no") == "yes"
}

// rootLogin: "yes" lets root in. The default, prohibit-password, lets root
// in only with a key, so it counts when root has keys we can see.
func rootLogin(fsys fs.FS, v string) bool {
	switch strings.ToLower(v) {
	case "yes":
		return true
	case "", "prohibit-password", "without-password":
		data, err := fs.ReadFile(fsys, "root/.ssh/authorized_keys")
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return true
			}
		}
	}
	return false
}

func parseSSHDT(out []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok {
			m[strings.ToLower(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// parseSSHDConfig reads etc/ssh/sshd_config and its Include files. The
// first value for a keyword wins, as in sshd. Settings inside a Match
// block apply only to some connections, so reading stops there.
func parseSSHDConfig(fsys fs.FS) (map[string]string, bool) {
	m := map[string]string{}
	if _, err := fs.Stat(fsys, "etc/ssh/sshd_config"); errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	readSSHFile(fsys, "etc/ssh/sshd_config", m, 0)
	return m, true
}

// readSSHFile returns false when a Match block was reached.
func readSSHFile(fsys fs.FS, name string, m map[string]string, depth int) bool {
	data, err := fs.ReadFile(fsys, name)
	if err != nil || depth > 8 {
		return true
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
		if len(f) < 2 {
			continue
		}
		key := strings.ToLower(f[0])
		switch key {
		case "match":
			return false
		case "include":
			for _, pattern := range f[1:] {
				pattern = strings.TrimPrefix(pattern, "/")
				if !strings.HasPrefix(pattern, "etc/") {
					pattern = path.Join("etc/ssh", pattern)
				}
				files, _ := fs.Glob(fsys, pattern)
				for _, file := range files {
					if !readSSHFile(fsys, file, m, depth+1) {
						return false
					}
				}
			}
		default:
			if _, set := m[key]; !set {
				m[key] = f[1]
			}
		}
	}
	return true
}
