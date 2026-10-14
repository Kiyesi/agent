package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// drillPoll is how often kiyesi drill looks at the steps going out. Tests shorten it.
var drillPoll = 5 * time.Second

func newDrill(io IO) *cobra.Command {
	var last, noWait, asJSON bool
	cmd := &cobra.Command{
		Use:   "drill",
		Short: "Send a practice incident through the escalation steps, and see who was reached",
		Long: "Each person in the escalation steps gets a message marked PRACTICE on the\n" +
			"channel a real incident would use, one minute apart. The result says who was\n" +
			"reached, how fast each acknowledged, and which channel failed and why. It\n" +
			"never shows on a status page and uses no credit.",
		Example: "  kiyesi drill\n  kiyesi drill --last\n  kiyesi drill --no-wait",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			var d *api.Drill
			if last {
				if d, err = c.LastDrill(cmd.Context()); err != nil {
					return drillErr(err)
				}
				if d == nil {
					fmt.Fprintln(io.Out, "No drill yet. Run one: kiyesi drill")
					return nil
				}
			} else {
				started, err := c.StartDrill(cmd.Context())
				if err != nil {
					return drillErr(err)
				}
				d = &started
				// The steps go out one minute apart: wait for them, unless asked not to.
				deadline := time.Now().Add(time.Duration(len(d.Steps))*time.Minute + 30*time.Second)
				for !noWait && !d.Done && time.Now().Before(deadline) {
					time.Sleep(drillPoll)
					if next, err := c.LastDrill(cmd.Context()); err == nil && next != nil && next.ID == d.ID {
						d = next
					}
				}
			}
			if asJSON {
				return render.JSON(io.Out, d)
			}
			printDrill(io, *d)
			return nil
		},
	}
	cmd.Flags().BoolVar(&last, "last", false, "show the last drill's result")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "start it and do not wait for the steps")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

func drillErr(err error) error {
	if errors.Is(err, api.ErrNotFound) {
		return &exitError{code: ExitUsage, msg: "Fire drills are for owners and admins: they set the escalation steps."}
	}
	return apiErr(err)
}

func printDrill(io IO, d api.Drill) {
	fmt.Fprintf(io.Out, "Fire drill, %s, by %s\n\n", d.StartedAt.Local().Format("Mon 2 Jan 15:04"), d.StartedBy)
	for _, s := range d.Steps {
		what := "waiting: steps go out one minute apart"
		switch {
		case s.SentAt == nil:
		case s.Delivered != nil && *s.Delivered:
			what = fmt.Sprintf("%s, delivered in %d s, ", deref(s.Via), derefInt(s.DeliveredInSeconds))
			if s.AckedInMinutes != nil {
				what += fmt.Sprintf("acknowledged in %d min", *s.AckedInMinutes)
			} else {
				what += "not acknowledged yet"
			}
		default:
			what = fmt.Sprintf("NOT REACHED: %s was not delivered: %s", deref(s.Via), deref(s.Reason))
		}
		fmt.Fprintf(io.Out, "  after %3d min  %-20s %s\n", s.RealMinutes, s.Name, what)
	}
	fmt.Fprintf(io.Out, "\n%s\n", d.Summary)
	if d.Done {
		fmt.Fprintln(io.Out, "Acknowledgements keep arriving: see them later with kiyesi drill --last")
	}
}

func derefInt(n *int) int {
	if n == nil {
		return 0
	}
	return *n
}
