package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var expiryKind = map[string]string{"domain": "domain", "certificate": "certificate", "date": "your date"}

func newRenewals(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "renewals",
		Short: "What runs out soon: domains, certificates and your own dates",
		Long: "Lists the expiry calendar, soonest first: the domains and certificates found\n" +
			"from your uptime checks, and the dates your team added. Kiyesi warns 30, 7 and\n" +
			"1 day before each. Add a date in the dashboard, on Renewals.",
		Example: "  kiyesi renewals\n  kiyesi renewals --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Expiries(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, list)
			}
			if len(list) == 0 {
				fmt.Fprintln(io.Out, "Nothing to renew yet. Add an uptime check for an https address, or a date in the dashboard.")
				return nil
			}
			w := tabwriter.NewWriter(io.Out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "WHEN\tWHAT\tKIND")
			for _, x := range list {
				when := "date not known: type it on Renewals"
				if x.ExpiresAt != nil && x.DaysLeft != nil {
					when = x.ExpiresAt.Format("2 Jan 2006") + " (" + daysWords(*x.DaysLeft, x.RanOut) + ")"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", when, x.Name, expiryKind[x.Kind])
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the list as JSON, for scripts")
	return cmd
}

// daysWords says when something runs out, in calendar days from today:
// "today", "tomorrow", "in 3 days", "ran out today", "ran out yesterday".
// ranOut says it already has, even when that was earlier today.
func daysWords(days int, ranOut bool) string {
	switch {
	case days < -1:
		return fmt.Sprintf("ran out %d days ago", -days)
	case days == -1:
		return "ran out yesterday"
	case days == 0 && ranOut:
		return "ran out today"
	case days == 0:
		return "today"
	case days == 1:
		return "tomorrow"
	}
	return fmt.Sprintf("in %d days", days)
}
