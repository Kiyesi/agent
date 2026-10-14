package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

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

func newConnect(io IO) *cobra.Command {
	var token, api string
	var noService bool
	cmd := &cobra.Command{
		Use:   "connect --token <token>",
		Short: "Link this server to the service and start sending results",
		Long: "Checks the token with the service, saves it where only root can read it, and\n" +
			"installs and starts the kiyesi system service. The service runs a scan now and\n" +
			"every 15 minutes, and says it is alive every minute. It only reads, opens no\n" +
			"port, and masks secrets before anything is sent.",
		Example: "  sudo kiyesi connect --token ksv_...",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 && os.Getenv("KIYESI_ETC") == "" {
				return usageErr("Connecting installs a system service, so it needs root. Run: sudo kiyesi connect --token <token>")
			}
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
	cmd.Flags().StringVar(&token, "token", "", "the server token, starting with ksv_")
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
	_, err := exec.LookPath("trivy")
	return err == nil
}

func unitFileFor(exe string, trivy bool) string {
	memory := "64M"
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
# 64 MB for the agent; 640 MB when Trivy is installed, which runs inside it.
MemoryMax=` + memory + `
TasksMax=64
NoNewPrivileges=yes
# Read any file (for root-only settings) and read firewall rules. Nothing else.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN
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

[Install]
WantedBy=multi-user.target
`
}

func installService(io IO) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
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
		cmd := exec.Command("systemctl", args...) // #nosec G204 -- fixed arguments
		cmd.Stdout, cmd.Stderr = io.Out, io.Err
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), err)
		}
	}

	return nil
}
