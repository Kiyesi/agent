package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func newCredit(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "credit",
		Short: "Your team's credit: the balance, days left, and what used it",
		Long: "One credit is one server for one day. Top up in the dashboard, under Credit:\n" +
			"nothing renews by itself and no card is kept.",
		Example: "  kiyesi credit",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			cr, err := c.Credit(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Your role cannot see credit. Owners, admins and Billing can."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, cr)
			}
			fmt.Fprintf(io.Out, "Balance: %s\n", plural(cr.Balance, "server-day", "server-days"))
			switch {
			case cr.DaysLeft == nil:
				fmt.Fprintln(io.Out, "Nothing was used in the last week, so it does not run out.")
			case cr.RunsOutOn != nil:
				fmt.Fprintf(io.Out, "About %s left, until %s, at %d server-days used in the last week.\n",
					plural(*cr.DaysLeft, "day", "days"), cr.RunsOutOn.Local().Format("2 Jan 2006"), cr.UsedLastWeek)
			}
			if !cr.State.Storing && cr.Live {
				fmt.Fprintln(io.Out, "\nNo credit, so the free plan: one server's scans and findings, alerts on Telegram, Slack\nand webhooks, and the status page at status.kiyesi.dev. Add credit for the rest.")
				if cr.State.EraseOn != nil {
					fmt.Fprintf(io.Out, "Stored history is deleted on %s unless you top up.\n", cr.State.EraseOn.Local().Format("2 Jan 2006"))
				}
			}
			if !cr.Live {
				fmt.Fprintln(io.Out, "\nCredit is not charged yet: everything works as before.")
			}
			if len(cr.Bundles) > 0 {
				fmt.Fprintln(io.Out, "\nTop up in the dashboard, under Credit:")
				for _, b := range cr.Bundles {
					fmt.Fprintf(io.Out, "  %d server-days for $%.2f (about $%.2f a server a month)\n", b.Credits, b.USD, b.PerServerMonth)
				}
			}
			if len(cr.Lines) > 0 {
				fmt.Fprintln(io.Out, "\nLatest:")
				for i, l := range cr.Lines {
					if i == 5 {
						break
					}
					fmt.Fprintf(io.Out, "  %s  %+d  %s\n", l.At.Local().Format("2 Jan"), l.Amount, l.Reason)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.AddCommand(&cobra.Command{
		Use:     "topup",
		Short:   "Open the Credit page in the browser, to top up",
		Long:    "You pay on Flutterwave's page, in the dashboard's Credit screen: the terminal never handles a card.",
		Example: "  kiyesi credit topup",
		Args:    cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			l, err := loadLogin()
			if err != nil {
				return err
			}
			openPage(io, dashboardURL(l.API)+"/credit/")
			return nil
		},
	})
	return cmd
}
