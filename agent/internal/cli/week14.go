package cli

import (
	"context"
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

var mapResults = map[string]string{"must_move": "MUST MOVE", "outside": "outside", "inside": "inside", "review": "for review"}
var mapSure = map[string]string{"confirmed": "confirmed", "likely": "likely", "set": "set by you", "unknown": "unknown"}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func newDatamap(io IO) *cobra.Command {
	var outside, asJSON, report bool
	var pdf string
	cmd := &cobra.Command{
		Use:   "datamap",
		Short: "Where every server, database and backup sits, against your home country",
		Long: "Lists every server, database, backup and outside service with its provider and\n" +
			"country, and flags payment data outside the home country. It is evidence of\n" +
			"where data sits, not a certificate of compliance.",
		Example: "  kiyesi datamap\n  kiyesi datamap --outside\n  kiyesi datamap --report --pdf data-map.pdf",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			if report {
				r, err := c.MakeDataMapReport(cmd.Context())
				if errors.Is(err, api.ErrNotFound) {
					return &exitError{code: ExitNoAccess, msg: "Your role cannot see the data map."}
				}
				if err != nil {
					return apiErr(err)
				}
				fmt.Fprintf(io.Out, "%s\n%s\n", r.Title, r.Summary)
				if pdf == "" {
					pdf = "data-map-" + r.Period + ".pdf"
				}
				return savePDF(cmd.Context(), io, c, r, pdf)
			}
			m, err := c.DataMap(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitNoAccess, msg: "Your role cannot see the data map."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, m)
			}
			if len(m.Rows) == 0 {
				fmt.Fprintln(io.Out, "Nothing is mapped yet. Each connected server's next scan adds its rows.")
				return nil
			}
			switch {
			case m.Home == nil:
				fmt.Fprintf(io.Out, "No home country chosen. Choose a home country in the dashboard, Data map, to compare against. %d mapped.\n\n", m.Counts.Mapped)
			case !m.Home.Chosen:
				fmt.Fprintf(io.Out, "Home country: %s (from the agents' settings). %d mapped, %d outside, %d payment data outside.\n\n", m.Home.Name, m.Counts.Mapped, m.Counts.Outside, m.Counts.MustMove)
			default:
				fmt.Fprintf(io.Out, "Home country: %s. %d mapped, %d outside, %d payment data outside.\n\n", m.Home.Name, m.Counts.Mapped, m.Counts.Outside, m.Counts.MustMove)
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "ITEM\tTYPE\tSERVER\tPROVIDER\tLOCATION\tHOW SURE\tRESULT")
			shown := 0
			for _, r := range m.Rows {
				if outside && r.Result != "outside" && r.Result != "must_move" {
					continue
				}
				shown++
				name := r.Name
				if r.Payment {
					name += " (payment data)"
				}
				kind := r.Kind
				if r.Managed {
					kind = "managed"
				}
				if r.Private {
					kind += " (private network)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, kind, r.ServerName, deref(r.Provider), deref(r.Place), mapSure[r.Confidence], mapResults[r.Result])
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if shown == 0 {
				fmt.Fprintln(io.Out, "Nothing to show.")
			}
			if m.IPinfo {
				fmt.Fprintln(io.Out, "\nIP address data is powered by IPinfo.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&outside, "outside", false, "only what sits outside the home country")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().BoolVar(&report, "report", false, "make the report for an auditor and save it")
	cmd.Flags().StringVar(&pdf, "pdf", "", "where to save the report (default data-map-<date>.pdf)")
	cmd.SetContext(context.Background())
	return cmd
}

// serverID finds a server by name, or "" for all of them.
func serverID(cmd *cobra.Command, c *api.Client, args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	list, err := c.Servers(cmd.Context())
	if err != nil {
		return "", apiErr(err)
	}
	s, ok := find(list, args[0])
	if !ok {
		return "", usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", args[0])
	}
	return s.ID, nil
}

func newTips(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "tips [server]",
		Short:   "Improvements that are not urgent, for each server",
		Example: "  kiyesi tips\n  kiyesi tips checkout-api-prod",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			id, err := serverID(cmd, c, args)
			if err != nil {
				return err
			}
			tips, err := c.Tips(cmd.Context(), id)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitNoAccess, msg: "Your role cannot see tips."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, tips)
			}
			if len(tips) == 0 {
				fmt.Fprintln(io.Out, "No tips: nothing to improve that Kiyesi can see.")
				return nil
			}
			for _, t := range tips {
				fmt.Fprintf(io.Out, "%s: %s\n  %s\n  %s\n\n", t.ServerName, t.Sentence, t.Why, t.Fix)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.SetContext(context.Background())
	return cmd
}

func newAdvisories(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "advisories [server]",
		Short: "Software past its end of life, and packages with published fixes for known flaws",
		Long: "Compares what each server has installed with endoflife.date and OSV, every day.\n" +
			"Advisories never change the grade and never send an alert.",
		Example: "  kiyesi advisories\n  kiyesi advisories checkout-api-prod",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			id, err := serverID(cmd, c, args)
			if err != nil {
				return err
			}
			rep, err := c.AdvisoryReport(cmd.Context(), id)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitNoAccess, msg: "Your role cannot see advisories."}
			}
			if err != nil {
				return apiErr(err)
			}
			list := rep.Advisories
			if asJSON {
				if list == nil {
					list = []api.Advisory{}
				}
				return render.JSON(io.Out, list)
			}
			// A server whose check failed is not "patched": say so, and
			// say all is well only when every server was checked.
			for _, e := range rep.Errors {
				name := e.ServerName
				if name == "" {
					name = "a server"
				}
				fmt.Fprintf(io.Out, "Not checked on %s: %s\n", name, e.Message)
			}
			if len(rep.Errors) > 0 {
				fmt.Fprintln(io.Out)
			}
			if rep.CheckedAt == nil {
				if len(rep.Errors) == 0 {
					fmt.Fprintln(io.Out, "Not checked yet: the agent (0.17.0 or newer) sends what is installed with its next scan.")
				}
				return nil
			}
			if len(list) == 0 {
				if len(rep.Errors) == 0 {
					fmt.Fprintln(io.Out, "Nothing to report: everything is supported and patched.")
				} else {
					fmt.Fprintln(io.Out, "Nothing to report on the servers that were checked.")
				}
				return nil
			}
			for _, a := range list {
				level := "when convenient"
				if a.Level == "high" {
					level = "ACT SOON"
				}
				fmt.Fprintf(io.Out, "[%s] %s: %s\n  %s\n  %s\n\n", level, a.ServerName, a.Sentence, a.Why, a.Fix)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.SetContext(context.Background())
	return cmd
}
