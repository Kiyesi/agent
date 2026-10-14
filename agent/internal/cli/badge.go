package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func newBadge(io IO) *cobra.Command {
	var asJSON, off bool
	cmd := &cobra.Command{
		Use:   "badge <server>",
		Short: "The grade badge for a project's README: turn it on and print the line to paste",
		Long: "A small image that shows the server's grade and links to Kiyesi. It shows the\n" +
			"grade only, never the server's name, and is off until you turn it on.\n" +
			"--off stops it at once; turning it on again gives it a new address.",
		Example: "  kiyesi badge checkout-api-prod\n  kiyesi badge checkout-api-prod --off",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			servers, err := c.Servers(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			s, ok := find(servers, args[0])
			if !ok {
				return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", args[0])
			}
			if off {
				if err := c.BadgeOff(cmd.Context(), s.ID); err != nil {
					return badgeErr(err)
				}
				fmt.Fprintf(io.Out, "The grade badge of %s is off: its image stops answering now.\n", s.Name)
				return nil
			}
			b, err := c.BadgeOn(cmd.Context(), s.ID)
			if err != nil {
				return badgeErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, b)
			}
			fmt.Fprintf(io.Out, "The grade badge of %s is on. Paste this into the README:\n\n%s\n\nIt shows the grade only. Stop it with: kiyesi badge %s --off\n", s.Name, b.Markdown, quoteArg(s.Name))
			return nil
		},
	}
	cmd.Flags().BoolVar(&off, "off", false, "turn the badge off")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.MarkFlagsMutuallyExclusive("off", "json")
	cmd.SetContext(context.Background())
	return cmd
}

// badgeErr: only people who manage a server can turn its badge on or off.
func badgeErr(err error) error {
	var p *api.Problem
	if errors.As(err, &p) && (p.Status == 403 || p.Status == 400) {
		code := ExitNoAccess
		if p.Status == 400 {
			code = ExitUsage
		}
		return &exitError{code: code, msg: p.Message}
	}
	return apiErr(err)
}
