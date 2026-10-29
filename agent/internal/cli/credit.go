package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// What the top-up lines say when no bundle can be bought here.
const (
	notSelling = "Top-ups are not open yet. Everything keeps working meanwhile."
	askBuyer   = "Ask an owner or someone with the Billing role to top up."
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
				return &exitError{code: ExitNoAccess, msg: "Your role cannot see credit. Owners, admins and Billing can."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, cr)
			}
			// The trial first: while it runs, its server needs no credit, and
			// credit already on the team waits for it to end.
			if cr.Trial.State == "active" && cr.Trial.EndsAt != nil {
				ends := cr.Trial.EndsAt.Local().Format("2 Jan 2006")
				fmt.Fprintf(io.Out, "Trial: %s left on %s, until %s.\n", plural(cr.Trial.DaysLeft, "day", "days"), cr.Trial.ServerName, ends)
				if cr.Balance > 0 {
					fmt.Fprintln(io.Out, "Your credit starts when the trial ends.")
				} else {
					fmt.Fprintln(io.Out, "Add credit before then to keep everything, or stay on the free plan.")
				}
				fmt.Fprintln(io.Out)
			}
			fmt.Fprintf(io.Out, "Balance: %s\n", plural(cr.Balance, "server-day", "server-days"))
			// At zero there is nothing left to run out: no days-left line.
			switch {
			case cr.Balance <= 0:
			case cr.DaysLeft == nil:
				fmt.Fprintln(io.Out, "Nothing was used in the last week, so it does not run out.")
			case cr.RunsOutOn != nil:
				fmt.Fprintf(io.Out, "About %s left, until %s, at the %s used in the last week.\n",
					plural(*cr.DaysLeft, "day", "days"), cr.RunsOutOn.Local().Format("2 Jan 2006"), plural(cr.UsedLastWeek, "server-day", "server-days"))
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
			// Bundles only for someone who can buy one, while top-ups are open.
			switch {
			case !cr.Selling:
				fmt.Fprintln(io.Out, "\n"+notSelling)
			case !cr.CanBuy:
				fmt.Fprintln(io.Out, "\n"+askBuyer)
			case len(cr.Bundles) > 0:
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := loadLogin()
			if err != nil {
				return err
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			cr, err := c.Credit(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitNoAccess, msg: askBuyer}
			}
			if err != nil {
				return apiErr(err)
			}
			if !cr.Selling {
				fmt.Fprintln(io.Out, notSelling)
				return nil
			}
			if !cr.CanBuy {
				return &exitError{code: ExitNoAccess, msg: askBuyer}
			}
			openPage(io, dashboardURL(l.API)+withTeam("/credit/", l.Team))
			return nil
		},
	})
	return cmd
}
