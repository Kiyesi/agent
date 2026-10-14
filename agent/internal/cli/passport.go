package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func newPassport(io IO) *cobra.Command {
	var asJSON, pdf, share bool
	cmd := &cobra.Command{
		Use:   "passport <server>",
		Short: "The server's passport: what runs on it, ports, jobs, people and how-to",
		Long: "Written by Kiyesi from what the agent sees, and rewritten after every scan, for\n" +
			"a handover or a client's question. It never shows passwords, keys or tokens.\n" +
			"Add --pdf to save it, or --share for a read-only link that lasts 7 days.",
		Example: "  kiyesi passport checkout-api-prod\n  kiyesi passport checkout-api-prod --pdf\n  kiyesi passport checkout-api-prod --share",
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
			switch {
			case pdf:
				data, err := c.PassportPDF(cmd.Context(), s.ID)
				if err != nil {
					return passportErr(err)
				}
				path := "passport-" + strings.ToLower(s.Name) + ".pdf"
				if err := os.WriteFile(path, data, 0o600); err != nil {
					return &exitError{code: ExitUsage, msg: fmt.Sprintf("cannot save %s: %v", path, err)}
				}
				fmt.Fprintf(io.Out, "Saved %s.\n", path)
				return nil
			case share:
				sh, err := c.SharePassport(cmd.Context(), s.ID)
				if err != nil {
					return passportErr(err)
				}
				fmt.Fprintf(io.Out, "%s\nRead-only, until %s. It shows the passport as it is now.\n", sh.URL, sh.ExpiresAt.Local().Format("2 January 2006"))
				return nil
			}
			p, err := c.Passport(cmd.Context(), s.ID)
			if err != nil {
				return passportErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, p)
			}
			printPassport(io, p)
			return nil
		},
	}
	cmd.Flags().BoolVar(&pdf, "pdf", false, "save it as a PDF in this folder")
	cmd.Flags().BoolVar(&share, "share", false, "make a read-only link that lasts 7 days")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.MarkFlagsMutuallyExclusive("pdf", "share", "json")
	cmd.SetContext(context.Background())
	return cmd
}

func passportErr(err error) error {
	var p *api.Problem
	if errors.As(err, &p) && p.Status == 403 {
		return &exitError{code: ExitNoAccess, msg: p.Message}
	}
	if errors.Is(err, api.ErrNotFound) {
		return &exitError{code: ExitUsage, msg: "Your role does not show server passports."}
	}
	return apiErr(err)
}

func printPassport(io IO, p api.Passport) {
	w := io.Out
	fmt.Fprintf(w, "Server passport: %s\nWritten by Kiyesi from what the agent sees. Passwords, keys and tokens are never shown.\n", p.Server)
	section := func(title string) { fmt.Fprintf(w, "\n%s\n", strings.ToUpper(title)) }
	section("What this server is for")
	if p.Note != nil {
		fmt.Fprintf(w, "  %s\n", p.Note.Text)
	} else {
		fmt.Fprintln(w, "  Not written yet: write it on the passport in the dashboard.")
	}
	if len(p.Runs) > 0 {
		section("What runs here")
		for _, r := range p.Runs {
			fmt.Fprintf(w, "  %-28s %s\n  %-28s %s\n", r.Name, r.Image, "", r.Restart)
		}
	}
	if len(p.Ports) > 0 {
		section("Ports open to the internet")
		words := map[string]string{"expected": "Expected", "check": "Check it", "close": "SHOULD BE CLOSED"}
		for _, x := range p.Ports {
			fmt.Fprintf(w, "  %-10s %-18s %s\n", x.Port, words[x.Status], x.What)
		}
	}
	if len(p.Jobs) > 0 {
		section("Scheduled jobs")
		for _, j := range p.Jobs {
			fmt.Fprintf(w, "  %-24s %-24s %s\n", j.Name, j.Schedule, j.Status)
		}
	}
	section("How to do the usual things")
	for _, u := range p.Usual {
		fmt.Fprintf(w, "  %s\n    %s\n", u.Title, u.Command)
	}
	pairs := func(title string, rows [][2]string) {
		if len(rows) == 0 {
			return
		}
		section(title)
		for _, r := range rows {
			fmt.Fprintf(w, "  %-18s %s\n", r[0], r[1])
		}
	}
	pairs("Facts", p.Facts)
	pairs("People", p.People)
	if len(p.DependsOn) > 0 {
		section("It depends on")
		for _, x := range p.DependsOn {
			fmt.Fprintf(w, "  %-28s %s\n", x.Name, x.What)
		}
	}
	if len(p.Changes) > 0 {
		section("Changed in the last 7 days")
		for _, x := range p.Changes {
			fmt.Fprintf(w, "  %s  %s\n", x.At.Local().Format("Mon 2 Jan 15:04"), x.Text)
		}
	}
	fmt.Fprintf(w, "\nHanding it over? kiyesi passport %s --pdf, or --share for a link that lasts 7 days.\n", p.Server)
}
