package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// What uninstall removes, and how it stops the service; tests replace them.
var (
	unitPath     = "/etc/systemd/system/kiyesi.service"
	runSystemctl = func(args ...string) error { return exec.Command("systemctl", args...).Run() } // #nosec G204 -- fixed arguments from this file
	hasSystemctl = func() bool { _, err := exec.LookPath("systemctl"); return err == nil }
	// Where install.sh may have put tab completion.
	completionFiles = []string{
		"/usr/share/bash-completion/completions/kiyesi", "/usr/local/etc/bash_completion.d/kiyesi",
		"/opt/homebrew/etc/bash_completion.d/kiyesi", "/usr/local/share/zsh/site-functions/_kiyesi",
		"/usr/share/fish/vendor_completions.d/kiyesi.fish", "/usr/local/share/fish/vendor_completions.d/kiyesi.fish",
		"/opt/homebrew/share/fish/vendor_completions.d/kiyesi.fish",
	}
	executablePath = os.Executable
)

func newUninstall(io IO) *cobra.Command {
	var yes, keepProgram bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the agent and its files from this server",
		Long: "Stops and removes the kiyesi service, the server token and settings in\n" +
			"/etc/kiyesi, the results waiting in /var/lib/kiyesi, and the kiyesi program.\n" +
			"What the server already sent stays in the dashboard: there, disconnect the\n" +
			"server to keep it until it expires, or delete it to erase it.\n\n" +
			"Changes made by kiyesi fix stay on the server, but their undo records go\n" +
			"with /var/lib/kiyesi, so kiyesi can no longer put them back. To put one back\n" +
			"first: sudo kiyesi fix undo",
		Example: "  sudo kiyesi uninstall",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 && os.Getenv("KIYESI_ETC") == "" {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi uninstall"}
			}
			var conf agentConf
			if data, err := os.ReadFile(agentConfPath()); err == nil {
				_ = yaml.Unmarshal(data, &conf)
			}
			if !yes {
				fmt.Fprintln(io.Err, "This removes the kiyesi service, its token and settings, its waiting results and the program from this server.")
				fmt.Fprintln(io.Err, "Changes made by kiyesi fix stay, and can no longer be undone with kiyesi. To put one back first: sudo kiyesi fix undo")
				if a := ask(io, "Type yes to go on: "); !strings.EqualFold(a, "yes") {
					return usageErr("Nothing was removed.")
				}
			}
			var problems []string
			if _, err := os.Stat(unitPath); err == nil && hasSystemctl() {
				if err := runSystemctl("disable", "--now", "kiyesi"); err != nil {
					problems = append(problems, "could not stop the service: "+err.Error())
				}
			}
			for _, p := range []string{unitPath, etcDir(), stateDir()} {
				if err := os.RemoveAll(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					problems = append(problems, fmt.Sprintf("could not remove %s: %v", p, err))
				}
			}
			if hasSystemctl() {
				_ = runSystemctl("daemon-reload")
			}
			if !keepProgram {
				for _, f := range completionFiles {
					if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
						problems = append(problems, fmt.Sprintf("could not remove %s: %v", f, err))
					}
				}
				if exe, err := executablePath(); err == nil {
					if exe, err = filepath.EvalSymlinks(exe); err == nil {
						if err := os.Remove(exe); err != nil {
							problems = append(problems, fmt.Sprintf("could not remove %s: %v", exe, err))
						}
					}
				}
			}
			if len(problems) > 0 {
				return &exitError{code: ExitNoAccess, msg: "Kiyesi is partly removed: " + strings.Join(problems, "; ")}
			}
			fmt.Fprintln(io.Out, "Kiyesi is removed from this server.")
			if conf.API != "" {
				fmt.Fprintln(io.Out, "What it sent is still in the dashboard. Open the server there and choose")
				fmt.Fprintln(io.Out, "Disconnect to keep it until it expires, or Delete to erase it.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask first")
	cmd.Flags().BoolVar(&keepProgram, "keep-program", false, "remove the service and its files but keep the kiyesi program, for one-off scans")
	return cmd
}
