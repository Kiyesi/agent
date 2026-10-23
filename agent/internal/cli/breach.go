package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/report"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

// breachAsRoot says whether the check runs as root. Tests replace it.
var breachAsRoot = func() bool { return os.Geteuid() == 0 }

func newBreachCheck(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "breach-check",
		Short: "Look for signs that someone already got into this server. Nothing leaves the server",
		Long: "Answers one question: has someone already got in? It compares the system's\n" +
			"programs with the packages they came from, and looks for crypto miners,\n" +
			"programs run from temporary folders, autostart entries that download and run\n" +
			"code, a second root account, a library loaded into every program, and history\n" +
			"or sign-in logs turned off. Each sign says what it means and what to do.\n" +
			"It only reads, needs root, and sends nothing. The same check runs in every scan.",
		Example: "  sudo kiyesi breach-check\n  sudo kiyesi breach-check --json   # exit 1 when there is a sign of a break-in",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !breachAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi breach-check\n" +
					"Other users' schedules, login keys and programs can be read only by root, and\n" +
					"\"no signs\" without them would mislead."}
			}
			pack, err := packs.English()
			if err != nil {
				return &exitError{code: ExitUsage, msg: "The built-in wording is damaged: " + err.Error() + ". Reinstall Kiyesi."}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			sys := newSystem(true, report.Dir(true))
			env := checks.NewEnv(sys, config.Default())
			r := scan.Run(ctx, env, checks.BreakIn(), pack)
			if asJSON {
				if err := render.JSON(io.Out, r.Checks); err != nil {
					return err
				}
			} else if err := render.BreakIn(render.NewWriter(io.Out, io.Environ), r); err != nil {
				return err
			}
			return failure(r, "critical")
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}
