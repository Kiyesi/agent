package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

var traceID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// thousands writes 8470 as "8,470".
func thousands(n int) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return "-" + thousands(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func answer(status *int) string {
	switch {
	case status == nil:
		return "-"
	case *status == 0:
		return "no answer"
	default:
		return fmt.Sprint(*status)
	}
}

func newTraces(io IO) *cobra.Command {
	var since, search string
	var all, asJSON bool
	cmd := &cobra.Command{
		Use:   "traces",
		Short: "Slow or failed requests, and where their time went",
		Long: "Lists requests followed by their ID from the browser through the web server\n" +
			"and the backend to the database, newest first: the slow (a second or more)\n" +
			"or failed ones, or all with --all. Open one with: kiyesi trace <id>",
		Example: "  kiyesi traces\n  kiyesi traces --all --since 1h --search /api/orders",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rng := map[string]string{"1h": "1h", "hour": "1h", "24h": "24h", "1d": "24h", "today": "24h", "7d": "7d", "week": "7d"}[strings.ToLower(since)]
			if rng == "" {
				return usageErr("--since must be 1h, 24h or 7d, not %q", since)
			}
			filter := "slow"
			if all {
				filter = "all"
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			rows, err := c.Traces(cmd.Context(), filter, search, rng)
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, rows)
			}
			if len(rows) == 0 {
				if all {
					fmt.Fprintln(io.Out, "No requests with an ID in that time.")
				} else {
					fmt.Fprintln(io.Out, "No slow or failed requests in that time. See the rest with --all.")
				}
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "TIME\tREQUEST\tANSWER\tTOOK\tWHERE THE TIME WENT\tID")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s %s\t%s\t%s ms\t%s\t%s\n", r.StartedAt.Local().Format("Mon 2 Jan 15:04:05"),
					r.Method, r.Path, answer(r.Status), thousands(r.TotalMs), r.Short, r.ID)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(io.Out, "\nOpen one with: kiyesi trace <id>")
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "every request, not only the slow or failed ones")
	cmd.Flags().StringVar(&since, "since", "24h", "how far back: 1h, 24h or 7d")
	cmd.Flags().StringVar(&search, "search", "", "a request ID, or an address such as /api/orders")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

var howNames = map[string]string{"measured": "measured", "matched": "matched by time", "worked_out": "worked out"}

// bar draws a step as it sits within the whole request, 30 characters wide.
func bar(s api.TraceStep, total int) string {
	const width = 30
	if total <= 0 {
		return ""
	}
	from := s.Offset * width / total
	n := (s.Ms*width + total - 1) / total
	if n < 1 {
		n = 1
	}
	if from+n > width {
		from = max(0, width-n)
	}
	return strings.Repeat("·", from) + strings.Repeat("█", n) + strings.Repeat("·", max(0, width-from-n))
}

func newTrace(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "trace <id>",
		Short:   "One request from the browser to the database, by its ID",
		Long:    "Shows one request as a row of steps, each with the time it took and how\nthat is known, where most of the time went, and its log lines.",
		Example: "  kiyesi trace req_2b77f0d3",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !traceID.MatchString(args[0]) {
				return usageErr("%q is not a request ID: 8 to 64 letters, digits, - or _.", args[0])
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			t, err := c.Trace(cmd.Context(), args[0])
			if err != nil {
				if errors.Is(err, api.ErrNotFound) {
					return &exitError{code: ExitUsage, msg: "No request with that ID that you can see in the last 7 days."}
				}
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, t)
			}
			fmt.Fprintf(io.Out, "%s %s   %s   %s ms in total   started %s\n%s\n\n", t.Method, t.Path, answer(t.Status),
				thousands(t.TotalMs), t.StartedAt.Local().Format("Mon 2 Jan 15:04:05"), t.ID)
			fmt.Fprintf(io.Out, "%s\n\n", t.Lead)
			if len(t.Steps) > 0 {
				// Labels to the left, times to the right, so the times line up.
				label, took := 0, 0
				for _, s := range t.Steps {
					label = max(label, len(s.Label))
					took = max(took, len(thousands(s.Ms)))
				}
				for _, s := range t.Steps {
					fmt.Fprintf(io.Out, "%-*s   %s   %*s ms   %s\n", label, s.Label, bar(s, t.TotalMs), took, thousands(s.Ms), howNames[s.How])
				}
				fmt.Fprintln(io.Out, "\nMeasured: a line with this request's ID gave the time. Matched by time: a slow\nquery at the same moment, likely, not certain. Worked out: the time left over.")
			}
			if len(t.Lines) > 0 {
				fmt.Fprintln(io.Out, "\nLog lines for this request:")
				for _, l := range t.Lines {
					text := summarize(l.Text)
					if text == "" {
						text = l.Text
					}
					fmt.Fprintf(io.Out, "  %s  %-5s  %s · %s  %s\n", l.At.Local().Format("15:04:05"), strings.ToUpper(l.Level), l.Name, l.Source, text)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}
