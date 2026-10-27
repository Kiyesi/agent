package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kiyesi/kiyesi/agent/internal/send"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// DefaultAPI is the hosted service. Teams that run Kiyesi on their own
// servers give their address with --api.
const DefaultAPI = "https://api.kiyesi.dev"

var tokenShape = regexp.MustCompile(`^ksv_[A-Za-z0-9_-]{43}$`)

// agentConf is /etc/kiyesi/agent.yaml.
type agentConf struct {
	API      string `yaml:"api"`
	ServerID string `yaml:"server_id"`
}

// tokenFrom finds the server token: --token, or --token - for the token
// on standard input, or KIYESI_TOKEN, or standard input when it is not a
// terminal. A token typed after --token shows in the list of processes
// while connect runs, so a one-line note says how to keep it out.
func tokenFrom(cmd *cobra.Command, flag string, in IO) (string, error) {
	switch {
	case flag == "-":
		return readToken(in.In)
	case cmd.Flags().Changed("token"):
		fmt.Fprintln(in.Err, "Note: a token after --token can be seen by other users while this runs. Safer: echo ksv_... | sudo kiyesi connect --token -")
		return flag, nil
	}
	if t := envMap(in.Environ)["KIYESI_TOKEN"]; t != "" {
		return t, nil
	}
	if in.In != nil {
		if f, ok := in.In.(*os.File); !ok || !term.IsTerminal(f.Fd()) {
			return readToken(in.In)
		}
	}
	return "", usageErr("Give the server token on standard input: echo ksv_... | sudo kiyesi connect --token -")
}

// readToken reads the first line of r, which is all a token needs.
func readToken(r io.Reader) (string, error) {
	if r == nil {
		return "", usageErr("No token on standard input. Run: echo ksv_... | sudo kiyesi connect --token -")
	}
	line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return line, nil
}

func newConnect(io IO) *cobra.Command {
	var token, api string
	var noService bool
	cmd := &cobra.Command{
		Use:   "connect [--token <token> | --token -]",
		Short: "Link this server to the service and start sending results",
		Long: "Checks the token with the service, saves it where only root can read it, and\n" +
			"installs and starts the kiyesi system service. The service runs a scan now and\n" +
			"every 15 minutes, and says it is alive every minute. On the free plan it\n" +
			"reports every 10 minutes and scans every 6 hours, as the service asks. It\n" +
			"only reads, opens no port, and masks secrets before anything is sent.\n\n" +
			"The token can come after --token, or on standard input with --token -, which\n" +
			"keeps it out of the list of processes other users can see, or in KIYESI_TOKEN.",
		Example: "  echo ksv_... | sudo kiyesi connect --token -\n  sudo kiyesi connect --token ksv_...",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 && os.Getenv("KIYESI_ETC") == "" {
				return usageErr("Connecting installs a system service, so it needs root. Run: sudo kiyesi connect --token <token>")
			}
			given, err := tokenFrom(cmd, token, io)
			if err != nil {
				return err
			}
			token = given
			token = strings.TrimSpace(token)
			if !tokenShape.MatchString(token) {
				return usageErr("That is not a server token. Copy the whole token, which starts with ksv_.")
			}
			if err := send.CheckAPI(api); err != nil {
				return usageErr("%v", err)
			}
			host, _ := os.Hostname()
			osName := system.ReadOS(os.DirFS("/")).Name
			c := send.NewClient(api, token)
			serverID, err := c.Connect(cmd.Context(), host, osName)
			switch {
			case errors.Is(err, send.ErrNotAllowed):
				return &exitError{code: ExitNoAccess, msg: "The service refused this token. It may have been revoked or mistyped: ask for a new one."}
			case err != nil:
				return &exitError{code: ExitNoAccess, msg: fmt.Sprintf("%v\nCheck the address and that this server can reach it over HTTPS, then try again.", err)}
			}
			if err := saveConnection(api, serverID, token); err != nil {
				return err
			}
			fmt.Fprintf(io.Out, "Connected %s to %s.\n", host, api)
			fmt.Fprintf(io.Out, "Saved the token to %s (readable by root only).\n", tokenPath())
			if noService {
				fmt.Fprintln(io.Out, "No service installed (--no-service). Run kiyesi agent to send results.")
				return nil
			}
			if err := installService(io); err != nil {
				return &exitError{code: ExitUsage, msg: err.Error()}
			}
			fmt.Fprintln(io.Out, "Started the kiyesi service. Results appear within a minute.")
			fmt.Fprintln(io.Out, "To stop sending: sudo systemctl disable --now kiyesi")
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "the server token, starting with ksv_, or - to read it from standard input")
	cmd.Flags().StringVar(&api, "api", DefaultAPI, "the service address; change it only for a service you run yourself")
	cmd.Flags().BoolVar(&noService, "no-service", false, "save the token but do not install the system service")
	return cmd
}

func saveConnection(api, serverID, token string) error {
	if err := os.MkdirAll(etcDir(), 0o750); err != nil {
		return err
	}
	if err := writeFile(tokenPath(), []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	data, err := yaml.Marshal(agentConf{API: api, ServerID: serverID})
	if err != nil {
		return err
	}
	return writeFile(agentConfPath(), data, 0o640)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// unitFile is the system service. It runs the agent as root, because some
// checks read files only root can read, and takes almost everything away:
// the system is read-only to it apart from its own folder, it may not gain
// privileges, and it has hard CPU and memory limits.
func unitFile(exe string) string {
	return unitFileFor(exe, hasTrivy())
}

// hasTrivy reports whether Trivy is installed. Trivy runs inside the
// service and needs about 400 MB to scan system packages.
func hasTrivy() bool {
	_, err := system.Find("trivy")
	return err == nil
}

func unitFileFor(exe string, trivy bool) string {
	memory := "256M"
	if trivy {
		memory = "640M"
	}
	return `[Unit]
Description=Kiyesi agent: read-only health and security checks
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + exe + ` agent
Restart=on-failure
RestartSec=30
Nice=10
IOSchedulingClass=idle
CPUQuota=20%
# 256 MB for the agent and the programs its checks run (apt-get alone needs
# about 120 MB); 640 MB when Trivy is installed, which runs inside it. A
# limit, not a reservation: the agent itself uses far less.
MemoryMax=` + memory + `
TasksMax=64
NoNewPrivileges=yes
# Read any file (for root-only settings) and read firewall rules. Nothing else.
# CAP_NET_ADMIN is there only because the kernel asks for it even to read the
# firewall: the firewall check runs nft list ruleset, iptables -S INPUT and
# ufw status, which all fail without it. No check or fix changes a rule.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN
# It never makes a set-user-ID file, and what it writes is for root alone.
RestrictSUIDSGID=yes
UMask=0077
RemoveIPC=yes
ProtectSystem=strict
ReadWritePaths=` + stateDir() + `
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=no
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# A database's password encrypted on this server (sudo kiyesi databases
# setup): systemd 254 and later decrypts it into a folder only this service
# reads, in memory. Older systemd ignores the line; the agent then reads
# Kiyesi's own encrypted file.
ImportCredential=kiyesi.db.*

[Install]
WantedBy=multi-user.target
`
}

// systemctl runs systemd's own program from root's folders, never one
// found first on PATH, as these run as root.
func systemctl(args ...string) *exec.Cmd {
	path, err := system.Find("systemctl")
	if err != nil {
		path = "/bin/systemctl"
	}
	return exec.Command(path, args...) // #nosec G204 -- systemd's program from a root folder, fixed arguments
}

func installService(io IO) error {
	if _, err := system.Find("systemctl"); err != nil {
		return errors.New("this system has no systemctl, so the service was not installed. Start kiyesi agent with your own service manager")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	if err := writeFile("/etc/systemd/system/kiyesi.service", []byte(unitFile(exe)), 0o644); err != nil {
		return fmt.Errorf("could not write the service file: %w", err)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "kiyesi"}, {"restart", "kiyesi"}} {
		cmd := systemctl(args...)
		cmd.Stdout, cmd.Stderr = io.Out, io.Err
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), err)
		}
	}

	return nil
}
