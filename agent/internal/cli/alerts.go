package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func newAlerts(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Show where alerts go, and what is open now",
		Example: "  kiyesi alerts\n" +
			"  kiyesi alerts test    # send a test message to every channel",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			channels, err := c.Channels(cmd.Context())
			var p *api.Problem
			hidden := errors.Is(err, api.ErrNotFound) || (errors.As(err, &p) && p.Status == 404)
			if err != nil && !hidden {
				return apiErr(err)
			}
			open, err := c.OpenAlerts(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, map[string]any{"channels": channels, "open": open})
			}
			if !hidden {
				if len(channels) == 0 {
					fmt.Fprintln(io.Out, "No alert channels yet. Add Telegram, Slack or email in the dashboard: Settings, Alerts.")
				} else {
					tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
					fmt.Fprintln(tw, "CHANNEL\tWHERE\tSTATE")
					for _, ch := range channels {
						state := "ready"
						if !ch.Linked {
							state = "waiting for Start in Telegram"
						}
						where := ch.Name
						if ch.Detail != "" && ch.Detail != ch.Name {
							where = ch.Detail
						}
						fmt.Fprintf(tw, "%s\t%s\t%s\n", ch.Kind, where, state)
					}
					if err := tw.Flush(); err != nil {
						return err
					}
				}
				fmt.Fprintln(io.Out)
			}
			if len(open) == 0 {
				fmt.Fprintln(io.Out, "No open alerts.")
				return nil
			}
			fmt.Fprintf(io.Out, "%s open:\n", plural(len(open), "alert", "alerts"))
			for _, a := range open {
				acked := ""
				if a.AckedAt != nil {
					acked = " (acknowledged)"
				}
				fmt.Fprintf(io.Out, "  %s: %s%s\n", a.Subject, strings.TrimSuffix(a.Sentence, "."), acked)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Send a test message to every alert channel",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			channels, err := c.Channels(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			failed := 0
			for _, ch := range channels {
				if !ch.Linked {
					fmt.Fprintf(io.Out, "SKIP  %s %s: not linked yet\n", ch.Kind, ch.Name)
					continue
				}
				if err := c.TestChannel(cmd.Context(), ch.ID); err != nil {
					failed++
					fmt.Fprintf(io.Out, "FAIL  %s %s: %v\n", ch.Kind, ch.Name, err)
					continue
				}
				fmt.Fprintf(io.Out, "SENT  %s %s\n", ch.Kind, ch.Name)
			}
			if len(channels) == 0 {
				fmt.Fprintln(io.Out, "No alert channels yet. Add one in the dashboard: Settings, Alerts.")
			}
			if failed > 0 {
				return &exitError{code: ExitFindings, msg: "Some test messages did not arrive. Check those channels in the dashboard."}
			}
			return nil
		},
	})
	cmd.SetContext(context.Background())
	return cmd
}

func newMute(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mute <server> <30m|2h|1d|off>",
		Short: "Silence a server's alerts for a set time. Every mute ends",
		Example: "  kiyesi mute checkout-api-prod 30m\n" +
			"  kiyesi mute checkout-api-prod off",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Servers(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			s, ok := find(list, args[0])
			if !ok {
				return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", args[0])
			}
			if args[1] == "off" {
				if err := c.Unmute(cmd.Context(), s.ID); err != nil {
					return apiErr(err)
				}
				fmt.Fprintf(io.Out, "Alerts for %s are on again.\n", s.Name)
				return nil
			}
			until, err := c.Mute(cmd.Context(), s.ID, args[1])
			var p *api.Problem
			if errors.As(err, &p) && p.Status == 400 {
				return usageErr("%s", p.Message)
			}
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "Alerts for %s are muted until %s. Turn them on sooner with: kiyesi mute %s off\n",
				s.Name, until.Local().Format("Mon 2 Jan 15:04"), s.Name)
			return nil
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}

func newUptime(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "uptime",
		Short: "Your uptime checks and their state",
		Example: "  kiyesi uptime\n" +
			"  kiyesi uptime add https://example.com/health",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			checks, err := c.Uptime(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, checks)
			}
			if len(checks) == 0 {
				fmt.Fprintln(io.Out, "No uptime checks yet. Add one: kiyesi uptime add https://example.com")
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "CHECK\tSTATUS\tRESPONSE\tLAST\tADDRESS")
			for _, u := range checks {
				resp, last := "-", "-"
				if u.Last != nil {
					last = ago(time.Since(u.Last.At)) + " ago"
					switch {
					case u.Last.MS != nil:
						resp = fmt.Sprintf("%d ms", *u.Last.MS)
					case u.Last.Error != nil:
						resp = *u.Last.Error
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Name, strings.ToUpper(u.Status), resp, last, u.URL)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	var name string
	add := &cobra.Command{
		Use:     "add <address>",
		Short:   "Check an address from outside every minute",
		Example: "  kiyesi uptime add https://example.com/health --name Shop",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			_, err = c.AddUptime(cmd.Context(), args[0], name)
			var p *api.Problem
			if errors.As(err, &p) && (p.Status == 400 || p.Status == 409) {
				return usageErr("%s", p.Message)
			}
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "Added. %s is checked from outside every minute; the first result arrives within a minute.\n", args[0])
			return nil
		},
	}
	add.Flags().StringVar(&name, "name", "", "a short name for the check")
	cmd.AddCommand(add, newUptimeEdit(io))
	cmd.SetContext(context.Background())
	return cmd
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
