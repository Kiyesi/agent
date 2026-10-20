package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A signed-in person's token lives in the system keychain: the macOS
// Keychain through `security`, or the Secret Service through `secret-tool`
// on Linux desktops. Where neither exists, such as on a server, it goes in
// a file only the user can read. The token is never put on a command line,
// where other users could see it in the process list.

const keychainService = "kiyesi"

// login is ~/.config/kiyesi/login.yaml: where the person signed in. The
// token is only here when no keychain could hold it.
type login struct {
	API   string `yaml:"api"`
	Token string `yaml:"token,omitempty"`
	// Team is which of the person's teams commands are for; empty for their oldest.
	Team string `yaml:"team,omitempty"`
}

// keyStore is the system keychain.
type keyStore interface {
	available() bool
	set(account, token string) error
	get(account string) (string, error)
	remove(account string) error
}

// keychain runs the system tools. Tests replace it.
var keychain keyStore = systemKeychain{}

type systemKeychain struct{}

func (systemKeychain) available() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := exec.LookPath("security")
		return err == nil
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err != nil {
			return false
		}
		// Without a desktop session there is no Secret Service to talk to.
		return os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""
	}
	return false
}

func (systemKeychain) set(account, token string) error {
	switch runtime.GOOS {
	case "darwin":
		// `security -i` reads its command from standard input, so the token
		// is not in the process list.
		cmd := exec.Command("security", "-i")
		cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -a %q -s %q -w %q\n", account, keychainService, token))
		return cmd.Run()
	default:
		cmd := exec.Command("secret-tool", "store", "--label=Kiyesi", "service", keychainService, "account", account) // #nosec G204 -- a fixed tool; account is the API address, passed as one argument with no shell
		cmd.Stdin = strings.NewReader(token)
		return cmd.Run()
	}
}

func (systemKeychain) get(account string) (string, error) {
	var out []byte
	var err error
	switch runtime.GOOS {
	case "darwin":
		out, err = exec.Command("security", "find-generic-password", "-a", account, "-s", keychainService, "-w").Output() // #nosec G204 -- a fixed tool; account is the API address, passed as one argument with no shell
	default:
		out, err = exec.Command("secret-tool", "lookup", "service", keychainService, "account", account).Output() // #nosec G204 -- a fixed tool; account is the API address, passed as one argument with no shell
	}
	return strings.TrimSpace(string(out)), err
}

func (systemKeychain) remove(account string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("security", "delete-generic-password", "-a", account, "-s", keychainService).Run() // #nosec G204 -- a fixed tool; account is the API address, passed as one argument with no shell
	default:
		return exec.Command("secret-tool", "clear", "service", keychainService, "account", account).Run() // #nosec G204 -- a fixed tool; account is the API address, passed as one argument with no shell
	}
}

func configDir() (string, error) {
	if d := os.Getenv("KIYESI_CONFIG"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "kiyesi"), nil
}

func loginPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "login.yaml"), nil
}

// savedLogin reads login.yaml as it is, with or without a token, so a new
// sign-in can keep the team chosen before. ok is false when there is none.
func savedLogin() (login, bool) {
	path, err := loginPath()
	if err != nil {
		return login{}, false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the user's own login file in their config folder
	if err != nil {
		return login{}, false
	}
	var l login
	if yaml.Unmarshal(data, &l) != nil || l.API == "" {
		return login{}, false
	}
	return l, true
}

// saveLogin keeps the token, in the keychain when there is one, and the
// team chosen with kiyesi team use. It says where the token went.
func saveLogin(api, token, team string) (string, error) {
	path, err := loginPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	// The folder may exist already, made by something else.
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil { // #nosec G302 -- a folder: 0700 is owner-only
		return "", err
	}
	l := login{API: api, Team: team}
	where := "the system keychain"
	if !keychain.available() || keychain.set(api, token) != nil {
		l.Token = token
		where = path + " (readable by you only)"
	}
	data, err := yaml.Marshal(l)
	if err != nil {
		return "", err
	}
	return where, writeFile(path, data, 0o600)
}

// saveTeam remembers which of the person's teams commands are for.
func saveTeam(teamID string) error {
	path, err := loginPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the user's own login file in their config folder
	if err != nil {
		return errSignedOut
	}
	var l login
	if err := yaml.Unmarshal(data, &l); err != nil || l.API == "" {
		return errSignedOut
	}
	l.Team = teamID
	out, err := yaml.Marshal(l)
	if err != nil {
		return err
	}
	return writeFile(path, out, 0o600)
}

// loadLogin returns where the person signed in and their token.
func loadLogin() (login, error) {
	path, err := loginPath()
	if err != nil {
		return login{}, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the user's own login file in their config folder
	if errors.Is(err, os.ErrNotExist) {
		return login{}, errSignedOut
	}
	if err != nil {
		return login{}, err
	}
	var l login
	if err := yaml.Unmarshal(data, &l); err != nil || l.API == "" {
		return login{}, errSignedOut
	}
	if l.Token == "" && keychain.available() {
		l.Token, _ = keychain.get(l.API)
	}
	if l.Token == "" {
		return login{}, errSignedOut
	}
	return l, nil
}

// forgetLogin removes the token from the keychain and the file.
func forgetLogin() error {
	path, err := loginPath()
	if err != nil {
		return err
	}
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- the user's own login file
		var l login
		if yaml.Unmarshal(data, &l) == nil && l.API != "" && keychain.available() {
			_ = keychain.remove(l.API)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

var errSignedOut = &exitError{code: ExitNoAccess, msg: "You are not signed in. Run: kiyesi login"}
