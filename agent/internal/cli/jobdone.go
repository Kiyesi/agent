package cli

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/jobs"
	"github.com/kiyesi/kiyesi/agent/internal/send"
)

// newJob is kiyesi job: telling Kiyesi how a timed job went. The job runs
// on its own, from its crontab or timer; Kiyesi never starts it.
func newJob(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "Tell Kiyesi how a timed job went, so a failed or missed run alerts you",
	}
	var startName string
	start := &cobra.Command{
		Use:   "start --name <job>",
		Short: "Record that a timed job is starting, before its command",
		Long: "Put it before the job's command in your crontab or systemd timer, and kiyesi\n" +
			"job done after it. It only records the start, so a run that does not start in\n" +
			"time is called missed, and one still going long after its usual time is called\n" +
			"running long. Kiyesi never starts the job.",
		Example: "  0 4 * * * /usr/local/bin/kiyesi job start --name nightly-backup; /opt/scripts/backup.sh; /usr/local/bin/kiyesi job done --name nightly-backup --exit $?\n" +
			"  ExecStartPre=/usr/local/bin/kiyesi job start --name nightly-backup",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !jobs.NamePattern.MatchString(startName) {
				return usageErr("Give the job a name with --name, using letters, digits, dots, dashes and underscores, such as nightly-backup.")
			}
			if err := jobs.RecordStart(filepath.Join(stateDir(), "runs"), startName, time.Now(), send.NewID); err != nil {
				return &exitError{code: ExitNoAccess, msg: fmt.Sprintf("This start was not recorded (%v). Is the agent running? sudo systemctl status kiyesi", err)}
			}
			return nil
		},
	}
	start.Flags().StringVar(&startName, "name", "", "the job's name, such as nightly-backup")

	var name, started, exit string
	done := &cobra.Command{
		Use:   "done --name <job> --exit <code>",
		Short: "Record that a timed job just ran, with its exit code",
		Long: "Put it after the job's command in your crontab or systemd timer, with kiyesi\n" +
			"job start before it. The job runs on its own, as it always did; this only\n" +
			"records how it went, and the agent sends it. Kiyesi never starts the job. It\n" +
			"finds the schedule from the same line, so a run that does not come in time is\n" +
			"called missed. The run is joined to the start kiyesi job start noted, for its\n" +
			"length; --started (seconds since 1970, from date +%s) gives it instead.",
		Example: "  0 4 * * * /usr/local/bin/kiyesi job start --name nightly-backup; /opt/scripts/backup.sh; /usr/local/bin/kiyesi job done --name nightly-backup --exit $?\n" +
			"  ExecStopPost=/usr/local/bin/kiyesi job done --name nightly-backup --exit $EXIT_STATUS",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !jobs.NamePattern.MatchString(name) {
				return usageErr("Give the job a name with --name, using letters, digits, dots, dashes and underscores, such as nightly-backup.")
			}
			code, err := strconv.Atoi(exit)
			if exit == "" || err != nil {
				return usageErr("Give the job's exit code with --exit, such as --exit $? right after its command, not %q.", exit)
			}
			now := time.Now()
			var from time.Time
			if started != "" {
				secs, err := strconv.ParseInt(started, 10, 64)
				if err != nil {
					return usageErr("--started is seconds since 1970, from date +%%s, not %q.", started)
				}
				from = time.Unix(secs, 0)
			}
			if err := jobs.Record(filepath.Join(stateDir(), "runs"), name, code, from, now, send.NewID); err != nil {
				return &exitError{code: ExitNoAccess, msg: fmt.Sprintf("This run was not recorded (%v). Is the agent running? sudo systemctl status kiyesi", err)}
			}
			return nil
		},
	}
	done.Flags().StringVar(&name, "name", "", "the job's name, such as nightly-backup")
	done.Flags().StringVar(&exit, "exit", "", "the job's exit code: $? right after its command, or $EXIT_STATUS in ExecStopPost")
	done.Flags().StringVar(&started, "started", "", "when the job began, in seconds since 1970 (date +%s)")
	cmd.AddCommand(start, done)
	return cmd
}
