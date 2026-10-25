package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/jobs"
	"github.com/kiyesi/kiyesi/agent/internal/send"
)

func newRun(io IO) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "run --name <job> -- <command>",
		Short: "Run a timed job and record it, so a failed or missed run alerts you",
		Long: "Runs the command exactly as it would run without Kiyesi: the same output\n" +
			"and exit code. Each run's start, end, exit code and last lines of output are\n" +
			"recorded, and the agent sends them. Put it in front of the command in your\n" +
			"crontab or systemd timer; Kiyesi reads the schedule from there.",
		Example: "  0 4 * * * /usr/local/bin/kiyesi run --name nightly-backup -- /opt/scripts/backup.sh",
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() < 0 || len(args) == 0 {
				return usageErr("Put the command after --, such as: kiyesi run --name nightly-backup -- /opt/scripts/backup.sh")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			in := io.In
			if in == nil {
				in = os.Stdin
			}
			spool := filepath.Join(stateDir(), "runs")
			// A bad name never stops the job: a backup in cron still runs,
			// only unrecorded, and stderr (cron's mail) says why.
			if !jobs.NamePattern.MatchString(name) {
				fmt.Fprintln(io.Err, "kiyesi run: this run is not recorded: give the job a name with --name, using letters, digits, dots, dashes and underscores, such as nightly-backup.")
				spool = ""
			}
			code := jobs.Execute(spool, name, args, in, io.Out, io.Err, send.NewID, time.Now)
			if code != 0 {
				return &exitError{code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "the job's name, such as nightly-backup")
	cmd.Flags().SetInterspersed(false)
	cmd.SetContext(context.Background())
	return cmd
}
