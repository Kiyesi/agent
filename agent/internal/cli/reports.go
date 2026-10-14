package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

var monthPattern = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

func newReports(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "Your monthly client reports and data map reports",
		Long: "Lists the reports you can see, newest first. Kiyesi makes each project's\n" +
			"monthly report on the first day of the month; make one for a past month with\n" +
			"kiyesi report.",
		Example: "  kiyesi reports",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Reports(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Your role cannot see reports."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, list.Reports)
			}
			if len(list.Reports) == 0 {
				fmt.Fprintln(io.Out, "No reports yet. Each project's monthly report is made on the first day of the\nmonth after it has a whole month of data.")
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "REPORT\tMADE\tSUMMARY")
			for _, r := range list.Reports {
				made := r.MadeAt.Local().Format("2 Jan 2006")
				if r.ByKiyesi {
					made += " (by Kiyesi)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Title, made, r.Summary)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the list as JSON")
	return cmd
}

func newReport(io IO) *cobra.Command {
	var project, month, pdf string
	var days int
	cmd := &cobra.Command{
		Use:   "report --project <name> --month <month>",
		Short: "Make a monthly report and print its share link",
		Long: "Makes a project's report for a whole past month, under your name and logo, and\n" +
			"prints a read-only link to send your client. --pdf saves it as a PDF too.\n" +
			"A month can be reported once it is over and the project has all of it.",
		Example: "  kiyesi report --project Checkout --month 2026-09\n" +
			"  kiyesi report --project Checkout --month 2026-09 --share 7 --pdf checkout-september.pdf",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if project == "" || !monthPattern.MatchString(month) {
				return usageErr("give --project and --month, such as --month 2026-09")
			}
			if days != 0 && days != 7 && days != 30 && days != 90 {
				return usageErr("--share is 7, 30 or 90 days, or 0 for no link")
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			list, err := c.Reports(ctx)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Your role cannot see reports."}
			}
			if err != nil {
				return apiErr(err)
			}
			id := ""
			for _, p := range list.Projects {
				if strings.EqualFold(p.Name, project) {
					id = p.ID
				}
			}
			if id == "" {
				return usageErr("there is no project called %q that you can report on", project)
			}
			r, err := c.MakeMonthly(ctx, id, month)
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "%s\n%s\n", r.Title, r.Summary)
			return shareAndSave(ctx, io, c, r, days, pdf)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "the project, by name")
	cmd.Flags().StringVar(&month, "month", "", "the month, such as 2026-09")
	cmd.Flags().IntVar(&days, "share", 30, "how many days the link works: 7, 30 or 90; 0 for no link")
	cmd.Flags().StringVar(&pdf, "pdf", "", "also save it as a PDF to this file")
	cmd.AddCommand(newReportCard(io))
	return cmd
}

// shareAndSave prints a share link and saves the PDF, as the person's role allows.
func shareAndSave(ctx context.Context, io IO, c *api.Client, r api.Report, days int, pdf string) error {
	if days > 0 {
		if !r.CanShare {
			fmt.Fprintln(io.Out, "\nYour role cannot make share links. Ask an owner for Create share links.")
		} else {
			s, err := c.ShareReport(ctx, r.ID, days)
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "\nShare link, read-only until %s:\n%s\n", s.ExpiresAt.Local().Format("2 Jan 2006"), s.URL)
		}
	}
	if pdf == "" {
		return nil
	}
	return savePDF(ctx, io, c, r, pdf)
}

// savePDF saves a report as a PDF, or as the same page in HTML when PDFs
// cannot be made just now.
func savePDF(ctx context.Context, io IO, c *api.Client, r api.Report, path string) error {
	if !r.CanDownload {
		return &exitError{code: ExitNoAccess, msg: "Your role cannot download files. Ask an owner for Download and export."}
	}
	data, err := c.ReportPDF(ctx, r.ID)
	var p *api.Problem
	if errors.As(err, &p) && p.Status == 503 {
		html, herr := c.ReportHTML(ctx, r.ID)
		if herr != nil {
			return apiErr(herr)
		}
		path = strings.TrimSuffix(path, ".pdf") + ".html"
		if err := os.WriteFile(path, []byte(html), 0o600); err != nil {
			return &exitError{code: ExitUsage, msg: fmt.Sprintf("cannot save %s: %v", path, err)}
		}
		fmt.Fprintf(io.Out, "%s\nSaved the same page as %s instead: print it from a browser.\n", p.Message, path)
		return nil
	}
	if err != nil {
		return apiErr(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return &exitError{code: ExitUsage, msg: fmt.Sprintf("cannot save %s: %v", path, err)}
	}
	fmt.Fprintf(io.Out, "Saved %s.\n", path)
	return nil
}

func newReportCard(io IO) *cobra.Command {
	var asJSON bool
	var thisWeek bool
	cmd := &cobra.Command{
		Use:   "card",
		Short: "The Monday report card: what was caught last week, what was fixed, and how fast",
		Long: "Counts the incidents and critical problems caught last week in what you can see,\n" +
			"how many were fixed and the typical time to fix. It never names who caused a\n" +
			"problem. Owners and admins get it by email on Monday mornings.",
		Example: "  kiyesi report card\n  kiyesi report card --this-week",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			card, err := c.Card(cmd.Context(), thisWeek)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Your role cannot see the report card."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, card)
			}
			fmt.Fprintf(io.Out, "%s\n%s\n", card.Content.Label, card.Content.Summary)
			return nil
		},
	}
	cmd.Flags().BoolVar(&thisWeek, "this-week", false, "this week so far, instead of last week")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}
