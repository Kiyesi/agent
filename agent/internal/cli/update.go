package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/update"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// Where releases come from, and where this program is. Tests replace them.
var (
	releases   = func() releaseSource { return update.DefaultSource(runtime.GOOS, runtime.GOARCH) }
	executable = func() (string, error) {
		p, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(p)
	}
)

type releaseSource interface {
	Latest(ctx context.Context) (string, error)
	Fetch(ctx context.Context) (update.Release, []byte, error)
}

func newUpdate(io IO) *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Install the newest kiyesi, after checking its signature",
		Long: "Downloads the newest release from get.kiyesi.dev, checks its signature with\n" +
			"the release key built into this program and the file's checksum, then\n" +
			"replaces this program in one step and restarts the agent if it runs.\n" +
			"Nothing is changed if any check fails. Updates never happen by themselves.",
		Example: "  kiyesi update --check\n  sudo kiyesi update",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			src := releases()
			latest, err := src.Latest(cmd.Context())
			if errors.Is(err, update.ErrUnreachable) {
				return &exitError{code: ExitNoAccess, msg: "This network cannot reach get.kiyesi.dev, after three tries.\n" +
					"If other sites open, this network's DNS is the likely cause: try another network,\n" +
					"or use Cloudflare's DNS (on a Mac: sudo networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1).\n" +
					"(" + err.Error() + ")"}
			}
			if err != nil {
				return &exitError{code: ExitNoAccess, msg: "Could not ask for the newest version: " + err.Error()}
			}
			if !update.Newer(latest, version.Version) {
				fmt.Fprintf(io.Out, "kiyesi %s is the newest.\n", version.Version)
				return nil
			}
			if check {
				fmt.Fprintf(io.Out, "kiyesi %s is out; this is %s. Install it with: sudo kiyesi update\n", latest, version.Version)
				return nil
			}
			exe, err := executable()
			if err != nil {
				return err
			}
			// Installed with Homebrew: Homebrew keeps it, so it updates it too.
			if strings.Contains(exe, "/Cellar/kiyesi/") {
				fmt.Fprintf(io.Out, "kiyesi %s is out; this is %s. Homebrew installed this one: brew upgrade kiyesi\n", latest, version.Version)
				return nil
			}
			rel, bin, err := src.Fetch(cmd.Context())
			if err != nil {
				return &exitError{code: ExitNoAccess, msg: err.Error() + "."}
			}
			if err := update.Replace(exe, bin); err != nil {
				if errors.Is(err, update.ErrPermission) {
					return &exitError{code: ExitNoAccess, msg: fmt.Sprintf("Cannot change %s as this user. Run: sudo kiyesi update", exe)}
				}
				return err
			}
			fmt.Fprintf(io.Out, "Updated kiyesi %s to %s, signature checked.\n", version.Version, rel.Version)
			if _, err := os.Stat(unitPath); err == nil && hasSystemctl() {
				// An agent someone stopped stays stopped: only a running
				// one is restarted.
				if runSystemctl("is-active", "--quiet", "kiyesi") != nil {
					fmt.Fprintln(io.Out, "The agent is stopped, so it stays stopped. It runs the new version when you start it: sudo systemctl start kiyesi")
					return nil
				}
				if err := runSystemctl("try-restart", "kiyesi"); err != nil {
					return &exitError{code: ExitNoAccess, msg: "The agent could not restart: run sudo systemctl restart kiyesi"}
				}
				fmt.Fprintln(io.Out, "The agent restarted on the new version.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only say whether a newer version is out")
	cmd.SetContext(context.Background())
	return cmd
}
