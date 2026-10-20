package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

var incidentRef = regexp.MustCompile(`^(?i:INC-)?\d{1,9}$`)

func checkRef(ref string) error {
	if !incidentRef.MatchString(ref) {
		return usageErr("%q is not an incident: give its number, such as INC-12.", ref)
	}
	return nil
}

func incidentErr(err error) error {
	if errors.Is(err, api.ErrNotFound) {
		return &exitError{code: ExitUsage, msg: "No incident with that number that you can see."}
	}
	return apiErr(err)
}

var certaintyWords = map[string]string{"confirmed": "confirmed", "likely": "likely", "unclear": "unclear"}

func sourceLine(i api.Incident) string {
	if i.Limited {
		return "-"
	}
	if i.Certainty == nil {
		return "naming…"
	}
	name := "not named"
	if i.SourceName != nil {
		name = strings.ToLower(*i.SourceName)
	}
	return name + ", " + certaintyWords[*i.Certainty]
}

// whoMoved is who acknowledged an incident and who fixed it, when, and the note.
func whoMoved(i api.Incident) []string {
	var out []string
	at := func(t time.Time) string { return t.Local().Format("Mon 2 Jan 15:04") }
	if i.Acked != nil {
		out = append(out, fmt.Sprintf("Acknowledged by %s, %s.", nameOr(i.Acked.By), at(i.Acked.At)))
	}
	if i.Fixed != nil {
		if i.Fixed.By == nil {
			out = append(out, fmt.Sprintf("Closed by itself, %s.", at(i.Fixed.At)))
		} else {
			out = append(out, fmt.Sprintf("Fixed by %s, %s.", *i.Fixed.By, at(i.Fixed.At)))
		}
		if i.Fixed.Note != nil && *i.Fixed.Note != "" {
			out = append(out, "What fixed it: "+*i.Fixed.Note)
		}
	}
	return out
}

func nameOr(by *string) string {
	if by == nil || *by == "" {
		return "a former teammate"
	}
	return *by
}

// nextSteps is the commands that apply to an incident now: Acknowledge only
// while nobody has, and nothing for a role that does not act on incidents.
func nextSteps(i api.Incident, mayAct bool) string {
	switch {
	case !mayAct || i.Limited || i.Status == "fixed":
		return ""
	case i.Status == "open":
		return fmt.Sprintf("kiyesi ack %s, then kiyesi resolve %s --note \"what fixed it\"", i.Ref, i.Ref)
	default:
		return fmt.Sprintf("kiyesi resolve %s --note \"what fixed it\"", i.Ref)
	}
}

// already is the service saying an Acknowledge or Mark fixed changed
// nothing, because it was done before: its words name who and when.
func already(err error) (string, bool) {
	var p *api.Problem
	if errors.As(err, &p) && p.Status == 409 && strings.HasPrefix(p.Code, "already_") && p.Message != "" {
		return p.Message, true
	}
	return "", false
}

// maxNote is the longest fix note the service keeps.
const maxNote = 500

func newIncidents(io IO) *cobra.Command {
	var status string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "incidents",
		Short: "Open incidents with their likely source and status",
		Long: "Lists incidents, newest first: each failure grouped from its symptoms, with\n" +
			"the likely source and how sure Kiyesi is. Open one with: kiyesi incident <id>",
		Example: "  kiyesi incidents\n  kiyesi incidents --status all",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if status != "open" && status != "fixed" && status != "all" {
				return usageErr("--status must be open, fixed or all, not %q", status)
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			out, err := c.Incidents(cmd.Context(), status)
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, out)
			}
			if len(out.Incidents) == 0 {
				fmt.Fprintln(io.Out, map[string]string{
					"open":  "No open incidents.",
					"fixed": "No fixed incidents yet.",
					"all":   "No incidents yet.",
				}[status])
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			for _, i := range out.Incidents {
				sev := map[string]string{"critical": "Critical", "warning": "Warning"}[i.Severity]
				where := "-"
				if i.Where != nil {
					where = *i.Where
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", i.Ref, sev, i.Title, sourceLine(i), where, i.Status)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(io.Out, "\nOpen one with: kiyesi incident <id>")
			return nil
		},
	}
	cmd.Flags().StringVar(&status, "status", "open", "open, fixed or all")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

func newIncident(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "incident <id>",
		Short:   "One incident: the likely source, the evidence, the timeline and the fix",
		Example: "  kiyesi incident INC-12",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkRef(args[0]); err != nil {
				return err
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			i, err := c.IncidentDetail(cmd.Context(), args[0])
			if err != nil {
				return incidentErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, i)
			}
			fmt.Fprintf(io.Out, "%s  %s\n%s, %s, started %s\n", i.Ref, i.Title, i.Severity, i.Status, i.StartedAt.Local().Format("Mon 2 Jan 15:04"))
			for _, l := range whoMoved(i) {
				fmt.Fprintln(io.Out, l)
			}
			fmt.Fprintln(io.Out)
			if i.Limited {
				fmt.Fprintln(io.Out, "You can see that this incident happened and its status. The evidence is for your team.")
				return nil
			}
			fmt.Fprintf(io.Out, "Likely source: %s\n%s\n", sourceLine(i), i.Sentence)
			if len(i.Evidence) > 0 {
				fmt.Fprintln(io.Out, "\nEvidence")
				verdicts := map[string]string{"points": "points here", "problem": "problem", "healthy": "healthy", "no_data": "no data"}
				areas := map[string]string{"browser": "Browser", "deploy": "Deploy", "backend": "Backend", "server": "Server", "database": "Database", "outside": "Outside service"}
				tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
				for _, e := range i.Evidence {
					fmt.Fprintf(tw, "  %s\t%s\t%s\n", areas[e.Area], e.Text, verdicts[e.Verdict])
				}
				if err := tw.Flush(); err != nil {
					return err
				}
			}
			if len(i.Timeline) > 0 {
				fmt.Fprintln(io.Out, "\nTimeline")
				for _, t := range i.Timeline {
					fmt.Fprintf(io.Out, "  %s  %s\n", t.At.Local().Format("15:04"), t.Text)
				}
			}
			if i.TeamNote != nil {
				by := ""
				if i.TeamNote.By != nil {
					by = " (" + *i.TeamNote.By + ")"
				}
				fmt.Fprintf(io.Out, "\nYour team's note from %s%s: %s\n", i.TeamNote.Ref, by, i.TeamNote.Note)
			}
			if i.Fix != nil {
				fmt.Fprintf(io.Out, "\nSuggested fix: %s\n  What happened. %s\n  Why it usually happens. %s\n  Fix. %s\n", strings.ToLower(i.Fix.Title), i.Fix.Happened, i.Fix.Why, i.Fix.Fix)
				if i.Fix.Command != nil {
					fmt.Fprintf(io.Out, "\n  %s\n", *i.Fix.Command)
				}
			}
			if h := nextSteps(i, mayDo(cmd.Context(), c, "incidents", "act")); h != "" {
				fmt.Fprintf(io.Out, "\n%s\n", h)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

func newAck(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ack <ref>",
		Short:   "Acknowledge an incident or any other work, so your team sees someone is on it",
		Example: "  kiyesi ack INC-12\n  kiyesi ack job-3f9a1c",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			// Work other than incidents: findings, browser errors, jobs, databases.
			if checkRef(args[0]) != nil {
				row, err := findWork(cmd.Context(), c, args[0])
				if err != nil {
					return err
				}
				if err := c.AckWork(cmd.Context(), row.Key); err != nil {
					if msg, ok := already(err); ok {
						return usageErr("%s %s", args[0], strings.TrimPrefix(msg, "It "))
					}
					return workErr(err)
				}
				fmt.Fprintf(io.Out, "Acknowledged %s. Your team can see someone is on it.\n", args[0])
				return nil
			}
			if err := c.AckIncident(cmd.Context(), args[0]); err != nil {
				if msg, ok := already(err); ok {
					return usageErr("%s", msg)
				}
				return incidentErr(err)
			}
			fmt.Fprintf(io.Out, "Acknowledged %s. Your team can see someone is on it.\n", strings.ToUpper(args[0]))
			return nil
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}

func newResolve(io IO) *cobra.Command {
	var note string
	cmd := &cobra.Command{
		Use:     "resolve <ref> --note \"what fixed it\"",
		Short:   "Mark an incident or any other work fixed, and save what fixed it",
		Long:    "Marks an incident fixed. The note shows first the next time the same failure happens.",
		Example: "  kiyesi resolve INC-12 --note \"Rolled back to 2.13.4, added the missing check\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(strings.TrimSpace(note)) < 3 {
				return usageErr("Say what fixed it with --note. It shows first the next time this happens.")
			}
			if n := len([]rune(strings.TrimSpace(note))); n > maxNote {
				return usageErr("The note is %d characters: keep it to %d, a line on what fixed it.", n, maxNote)
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			if checkRef(args[0]) != nil {
				row, err := findWork(cmd.Context(), c, args[0])
				if err != nil {
					return err
				}
				if err := c.FixWork(cmd.Context(), row.Key, note); err != nil {
					if msg, ok := already(err); ok {
						return usageErr("%s", msg)
					}
					return workErr(err)
				}
				fmt.Fprintf(io.Out, "Marked %s fixed. Your note shows first the next time this happens.\n", args[0])
				return nil
			}
			if err := c.ResolveIncident(cmd.Context(), args[0], note); err != nil {
				if msg, ok := already(err); ok {
					return usageErr("%s", msg)
				}
				return incidentErr(err)
			}
			fmt.Fprintf(io.Out, "Marked %s fixed. Your note shows first the next time this happens.\n", strings.ToUpper(args[0]))
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "what fixed it, in a line")
	cmd.SetContext(context.Background())
	return cmd
}

func newExplain(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "explain <id>",
		Short: "A plain paragraph about an incident, for a client or a manager",
		Long: "Written from the same pattern as the fix, with no technical terms and no\n" +
			"server, file or teammate's name. No AI. Read it before you send it.",
		Example: "  kiyesi explain INC-11\n  kiyesi explain INC-11 | pbcopy",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkRef(args[0]); err != nil {
				return err
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			i, err := c.IncidentDetail(cmd.Context(), args[0])
			if err != nil {
				return incidentErr(err)
			}
			if i.Explain == nil {
				if i.Limited {
					return &exitError{code: ExitNoAccess, msg: "The paragraph is for your team: your role sees only that this incident happened."}
				}
				return usageErr("%s is still being looked at. The paragraph is ready within a minute of it opening.", i.Ref)
			}
			if asJSON {
				return render.JSON(io.Out, map[string]string{"ref": i.Ref, "paragraph": *i.Explain})
			}
			fmt.Fprintln(io.Out, *i.Explain)
			if stdoutIsTerminal(io) {
				fmt.Fprintln(io.Err, "\nIt leaves out server names, file names and teammates' names. Read it before you send it.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}
