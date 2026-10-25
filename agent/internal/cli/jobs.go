package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func tookWords(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", ms)
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Round(time.Second).Seconds()))
	default:
		m := int(d / time.Minute)
		s := int((d % time.Minute).Round(time.Second).Seconds())
		if s == 0 {
			return fmt.Sprintf("%d min", m)
		}
		return fmt.Sprintf("%d min %d s", m, s)
	}
}

var jobStatus = map[string]string{
	"new": "waiting for a run", "on_time": "on time", "running": "running",
	"long": "RUNNING LONG", "failed": "FAILED", "missed": "MISSED",
}

func newJobs(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "jobs [name]",
		Short: "Scheduled jobs with their last run and status",
		Long: "Lists the timed jobs wrapped with kiyesi run: when each runs, its last run,\n" +
			"how long it took, when it is next expected, and whether it failed, ran long or\n" +
			"did not run. Give a job's name to see its recent runs.",
		Example: "  kiyesi jobs\n  kiyesi jobs nightly-backup",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Jobs(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if len(args) == 1 {
				var found *api.Job
				for i := range list {
					if strings.EqualFold(list[i].Name, args[0]) {
						found = &list[i]
					}
				}
				if found == nil {
					return usageErr("There is no job called %q that you can see.", args[0])
				}
				j, err := c.JobDetail(cmd.Context(), found.ID)
				if err != nil {
					return apiErr(err)
				}
				if asJSON {
					return render.JSON(io.Out, j)
				}
				fmt.Fprintf(io.Out, "%s on %s: %s\n", j.Name, j.Server.Name, jobStatus[j.Status])
				if j.Problem != nil {
					fmt.Fprintln(io.Out, j.Problem.Text+".")
				}
				fmt.Fprintln(io.Out)
				for _, r := range j.Runs {
					state := "running"
					if r.ExitCode != nil {
						state = "ok"
						if *r.ExitCode != 0 {
							state = fmt.Sprintf("exit code %d", *r.ExitCode)
						}
					}
					took := ""
					if r.DurationMs != nil {
						took = ", " + tookWords(*r.DurationMs)
					}
					fmt.Fprintf(io.Out, "  %s  %s%s\n", r.StartedAt.Local().Format("Mon 2 Jan 15:04"), state, took)
					if r.ExitCode != nil && *r.ExitCode != 0 {
						for _, l := range r.LastLines {
							fmt.Fprintf(io.Out, "      %s\n", l)
						}
					}
				}
				return nil
			}
			if asJSON {
				return render.JSON(io.Out, list)
			}
			if len(list) == 0 {
				fmt.Fprintln(io.Out, "No jobs watched yet. Put kiyesi run in front of a job's command:\n\n  0 4 * * * /usr/local/bin/kiyesi run --name nightly-backup -- /opt/scripts/backup.sh")
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "JOB\tSERVER\tRUNS\tLAST RUN\tTOOK\tNEXT EXPECTED\tSTATUS")
			for _, j := range list {
				runs, last, took, next := "not found yet", "not yet", "-", "-"
				if j.Schedule != nil {
					runs = j.Schedule.Words
				}
				if j.LastRun != nil {
					last = j.LastRun.StartedAt.Local().Format("Mon 2 Jan 15:04")
					took = tookWords(j.LastRun.DurationMs)
					if j.UsualMs != nil && j.LastRun.DurationMs > 2**j.UsualMs {
						took += ", usually " + tookWords(*j.UsualMs)
					}
				}
				if j.NextExpected != nil {
					next = j.NextExpected.Local().Format("Mon 2 Jan 15:04")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", j.Name, j.Server.Name, runs, last, took, next, jobStatus[j.Status])
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}
