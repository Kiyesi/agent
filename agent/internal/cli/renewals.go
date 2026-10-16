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
				switch {
				case x.ExpiresAt == nil || x.DaysLeft == nil:
				case *x.DaysLeft < 0:
					when = fmt.Sprintf("%s (ran out %d days ago)", x.ExpiresAt.Format("2 Jan 2006"), -*x.DaysLeft)
				case *x.DaysLeft == 0:
					when = x.ExpiresAt.Format("2 Jan 2006") + " (today)"
				default:
					when = fmt.Sprintf("%s (in %d days)", x.ExpiresAt.Format("2 Jan 2006"), *x.DaysLeft)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", when, x.Name, expiryKind[x.Kind])
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the list as JSON, for scripts")
	return cmd
}
