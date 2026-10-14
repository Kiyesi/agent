package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// Short names for each kind of work, so a reference is easy to type:
// INC-12 for an incident, job-3f9a1c for a job.
var kindPrefix = map[string]string{
	"finding":       "finding",
	"browser_error": "error",
	"job":           "job",
	"database":      "db",
}

var kindWords = map[string]string{
	"incident":      "Incident",
	"finding":       "Finding",
	"browser_error": "Browser error",
	"job":           "Scheduled job",
	"database":      "Database",
}

var incPrefix = regexp.MustCompile(`^INC-\d+`)
var notAlnum = regexp.MustCompile(`[^a-z0-9]`)

// workRef is how a piece of work is named on the command line.
func workRef(r api.WorkRow) string {
	if r.Kind == "incident" {
		if m := incPrefix.FindString(r.Title); m != "" {
			return m
		}
	}
	tail := notAlnum.ReplaceAllString(strings.ToLower(r.Key), "")
	if len(tail) > 6 {
		tail = tail[len(tail)-6:]
	}
	return kindPrefix[r.Kind] + "-" + tail
}

// allRows is every row of a work list, unassigned first.
func allRows(l api.WorkList) []api.WorkRow {
	rows := append([]api.WorkRow{}, l.Unassigned...)
	for _, p := range l.People {
		rows = append(rows, p.Items...)
	}
	return rows
}

// findWork turns a reference into the open item it names.
func findWork(ctx context.Context, c *api.Client, ref string) (api.WorkRow, error) {
	list, err := c.Work(ctx, "everyone")
	if err != nil {
		return api.WorkRow{}, workErr(err)
	}
	for _, r := range allRows(list) {
		if strings.EqualFold(workRef(r), ref) {
			return r, nil
		}
	}
	return api.WorkRow{}, usageErr("Nothing open called %s that you can see. List it with: kiyesi mine --all", ref)
}

func workErr(err error) error {
	if errors.Is(err, api.ErrNotFound) {
		return &exitError{code: ExitUsage, msg: "Assigned work is not part of your access."}
	}
	return apiErr(err)
}

func printWork(io IO, rows []api.WorkRow) error {
	tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
	for _, r := range rows {
		state := map[string]string{"open": "open", "acknowledged": "acknowledged"}[r.State]
		where := r.Where
		if where == "" {
			where = "-"
		}
		owner := "-"
		if r.Owner != nil {
			owner = r.Owner.Name
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", workRef(r), kindWords[r.Kind], r.Title, where, state, owner)
	}
	return tw.Flush()
}

func newMine(io IO) *cobra.Command {
	var all, asJSON bool
	cmd := &cobra.Command{
		Use:   "mine",
		Short: "Everything assigned to you, and what nobody owns yet",
		Long: "Lists the incidents, findings, browser errors, jobs and database warnings\n" +
			"given to you, then those without an owner. Take one with: kiyesi assign <ref> me",
		Example: "  kiyesi mine\n  kiyesi mine --all",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Work(cmd.Context(), "everyone")
			if err != nil {
				return workErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, list)
			}
			var mine []api.WorkRow
			for _, p := range list.People {
				if p.You {
					mine = p.Items
				}
			}
			if list.Incomplete {
				fmt.Fprintln(io.Out, "Some items could not be loaded just now, so this list may be short.")
			}
			fmt.Fprintf(io.Out, "Assigned to you (%d)\n", len(mine))
			if len(mine) == 0 {
				fmt.Fprintln(io.Out, "Nothing.")
			} else if err := printWork(io, mine); err != nil {
				return err
			}
			fmt.Fprintf(io.Out, "\nNobody owns yet (%d)\n", len(list.Unassigned))
			if len(list.Unassigned) == 0 {
				fmt.Fprintln(io.Out, "Nothing.")
			} else if err := printWork(io, list.Unassigned); err != nil {
				return err
			}
			if all {
				for _, p := range list.People {
					if p.You {
						continue
					}
					fmt.Fprintf(io.Out, "\n%s (%d open)\n", p.Name, p.Open)
					if err := printWork(io, p.Items); err != nil {
						return err
					}
				}
			}
			fmt.Fprintln(io.Out, "\nkiyesi assign <ref> <teammate>, kiyesi ack <ref>, kiyesi resolve <ref> --note \"what fixed it\"")
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "also list what everyone else owns")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

func newAssign(io IO) *cobra.Command {
	var note string
	cmd := &cobra.Command{
		Use:   "assign <ref> <teammate>",
		Short: "Give an incident, finding, error, job or database warning to someone",
		Long: "Gives one piece of work to a teammate, by name, or to you with \"me\". They are\n" +
			"told on their own alert channel, with the evidence, the fix and your note.\n" +
			"With only the reference, says who Kiyesi suggests and why.",
		Example: "  kiyesi assign INC-12\n  kiyesi assign INC-12 Amaka --note \"Started after 3.8.1\"\n  kiyesi assign job-3f9a1c me",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			row, err := findWork(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			s, err := c.SuggestOwner(cmd.Context(), row.Key)
			if err != nil {
				return workErr(err)
			}
			if len(args) == 1 {
				fmt.Fprintln(io.Out, row.Title)
				if s.Suggestion != nil {
					fmt.Fprintf(io.Out, "Suggested: %s\n", s.Suggestion.Reason)
				} else {
					fmt.Fprintln(io.Out, "No suggestion: nobody's area matches, and nobody is on call.")
				}
				fmt.Fprintln(io.Out, "\nIt can go to:")
				for _, p := range s.Candidates {
					fmt.Fprintf(io.Out, "  %s (%d open)\n", p.Name, p.Open)
				}
				if len(s.NotListed) > 0 {
					fmt.Fprintf(io.Out, "Not listed, as their access does not include it: %s\n", strings.Join(s.NotListed, ", "))
				}
				return nil
			}
			want := strings.ToLower(strings.TrimSpace(args[1]))
			var to, name string
			for _, p := range s.Candidates {
				full := strings.ToLower(p.Name)
				first := strings.Fields(full)
				if (want == "me" && p.You) || full == want || (len(first) > 0 && first[0] == want) {
					if to != "" && to != p.ID {
						return usageErr("More than one person is called %s. Give the full name.", args[1])
					}
					to, name = p.ID, p.Name
				}
			}
			if to == "" {
				names := make([]string, 0, len(s.Candidates))
				for _, p := range s.Candidates {
					names = append(names, p.Name)
				}
				return usageErr("%s cannot be given this: they are not in the team, or cannot see it. It can go to: %s.", args[1], strings.Join(names, ", "))
			}
			if err := c.Assign(cmd.Context(), row.Key, to, note); err != nil {
				return workErr(err)
			}
			if want == "me" {
				fmt.Fprintf(io.Out, "%s is yours.\n", workRef(row))
			} else {
				fmt.Fprintf(io.Out, "Gave %s to %s. They are told on their own alert channel.\n", workRef(row), name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "a note they see with the alert")
	cmd.SetContext(context.Background())
	return cmd
}

func newTeam(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "team",
		Short:   "List teammates: role, what they can see, what they work on",
		Example: "  kiyesi team\n  kiyesi team invite seun@example.com --role member --area backend",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			r, err := c.Team(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "The team list is for owners and admins."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, r)
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "NAME\tROLE\tCAN SEE\tWORKS ON\tALERTS GO TO\tTWO-STEP")
			for _, p := range r.People {
				name := p.Name
				if p.You {
					name += " (you)"
				}
				area := "-"
				if p.Area != nil {
					area = map[string]string{"frontend": "Frontend", "backend": "Backend", "database": "Database", "devops": "DevOps"}[*p.Area]
				}
				two := "on"
				if !p.TwoStep {
					two = "not set up"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", name, p.Role.Name, p.CanSee, area, p.AlertsGoTo, two)
			}
			for _, i := range r.Invites {
				state := "invited, not joined yet"
				if i.Expired {
					state = "invite expired"
				}
				fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t%s\n", i.Email, i.Role.Name, state)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.AddCommand(newTeamInvite(io), newTeamRoles(io), newTeamAccess(io), newTeamUse(io), newTeamLeave(io))
	cmd.SetContext(context.Background())
	return cmd
}

func newTeamInvite(io IO) *cobra.Command {
	var role, area string
	cmd := &cobra.Command{
		Use:     "invite <email>",
		Short:   "Invite someone by email into a role",
		Long:    "Emails an invite that works once, for 7 days. They choose a password and set up\nan authenticator app. Only an owner can invite owners and admins.",
		Example: "  kiyesi team invite seun@example.com --role member --area backend",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			roles := map[string]bool{"owner": true, "admin": true, "member": true, "viewer": true, "billing": true, "client": true}
			if !roles[role] {
				return usageErr("--role must be owner, admin, member, viewer, billing or client, not %q", role)
			}
			if area != "" && area != "frontend" && area != "backend" && area != "database" && area != "devops" {
				return usageErr("--area must be frontend, backend, database or devops, not %q", area)
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			out, err := c.InvitePerson(cmd.Context(), args[0], role, area)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Inviting people is for owners and admins."}
			}
			if err != nil {
				return apiErr(err)
			}
			if out.Emailed {
				fmt.Fprintf(io.Out, "Invite sent to %s. It works once, for 7 days.\n", args[0])
				return nil
			}
			fmt.Fprintf(io.Out, "Email is not set up, so give %s this link yourself. It works once, for 7 days:\n\n  %s\n", args[0], out.Link)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "member", "owner, admin, member, viewer, billing or client")
	cmd.Flags().StringVar(&area, "area", "", "what they work on: frontend, backend, database or devops")
	cmd.SetContext(context.Background())
	return cmd
}

func newActivity(io IO) *cobra.Command {
	var asJSON bool
	var limit int
	cmd := &cobra.Command{
		Use:     "activity",
		Short:   "Who did what, newest first",
		Long:    "The activity log: every change anyone made, sign-ins, and what Kiyesi did by\nitself, such as an escalation. Kept 12 months.",
		Example: "  kiyesi activity\n  kiyesi activity --limit 100",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > 100 {
				return usageErr("--limit must be from 1 to 100")
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			lines, err := c.Activity(cmd.Context(), limit)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "The activity log is for owners and admins."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, lines)
			}
			if len(lines) == 0 {
				fmt.Fprintln(io.Out, "Nothing yet. Every change anyone makes appears here.")
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			for _, l := range lines {
				who := "Kiyesi"
				if l.By != nil {
					who = l.By.Name
				} else if l.ByLabel != nil {
					who = *l.ByLabel
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", l.At.Local().Format("2 Jan 15:04"), who, l.Sentence)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 30, "how many lines, up to 100")
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}
