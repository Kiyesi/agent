package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// The 19 areas in the menu's order, in words, for what a role can do.
var areaWords = []struct{ key, words string }{
	{"servers", "servers and findings"}, {"passports", "server passports"}, {"metrics", "metrics"},
	{"logs", "logs"}, {"traces", "traces"}, {"browser_errors", "browser errors"}, {"databases", "databases"},
	{"incidents", "incidents and assigned work"}, {"uptime", "uptime"}, {"scheduled_jobs", "scheduled jobs"},
	{"history", "history and deploys"}, {"data_map", "the data map"}, {"costs", "costs"}, {"reports", "reports"},
	{"tips", "tips and advisories"}, {"settings", "settings"}, {"team", "team and roles"}, {"credit", "credit"},
	{"activity", "the activity log"},
}

// areasAt lists the areas whose level is one of those given.
func areasAt(levels map[string]string, want ...string) string {
	var out []string
	for _, a := range areaWords {
		for _, w := range want {
			if levels[a.key] == w {
				out = append(out, a.words)
			}
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

func newWhoami(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "whoami",
		Short:   "Your role, what you can see, and when your access ends",
		Example: "  kiyesi whoami",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			a, err := c.WhoAmI(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, a)
			}
			team := "your team"
			if a.Team != nil {
				team = *a.Team
			}
			fmt.Fprintf(io.Out, "%s in %s.\n", a.Role.Name, team)
			fmt.Fprintf(io.Out, "Where: %s.\n", a.CanSee)
			if a.EndsAt != nil {
				fmt.Fprintf(io.Out, "Until: %s, then it stops by itself.\n", a.EndsAt.UTC().Format("2 January 2006"))
			} else {
				fmt.Fprintln(io.Out, "Until: for good.")
			}
			fmt.Fprintf(io.Out, "\nCan see: %s.\n", areasAt(a.Levels, "view", "act", "manage"))
			fmt.Fprintf(io.Out, "Can act on: %s.\n", areasAt(a.Levels, "act", "manage"))
			fmt.Fprintf(io.Out, "Can set up: %s.\n", areasAt(a.Levels, "manage"))
			return nil
		},
	}
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}

func newTeamRoles(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "roles",
		Short:   "List the roles and what each one allows",
		Example: "  kiyesi team roles",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			roles, err := c.Roles(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Roles are for owners and admins."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, roles)
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "ROLE\tKIND\tPEOPLE\tCAN ACT ON\tNEVER SEES")
			for _, r := range roles {
				kind := "built in"
				if !r.BuiltIn {
					kind = "made by you"
					if r.CopiedFrom != nil {
						kind = "made from " + *r.CopiedFrom
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", r.Name, kind, len(r.People), areasAt(r.Levels, "act", "manage"), areasAt(r.Levels, "hidden"))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(io.Out, "\nGive one with: kiyesi team access <person> --role <role>")
			return nil
		},
	}
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}

var dayPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func newTeamAccess(io IO) *cobra.Command {
	var role, projects, leaveOut, until, code string
	var forGood bool
	cmd := &cobra.Command{
		Use:   "access <person>",
		Short: "Set one person's role, where it applies and when it ends",
		Long: "Sets a teammate's role, the projects it applies in (all of them unless you\n" +
			"name some), servers left out, and the day it ends. It applies on their next\n" +
			"click. Asks for the code from your authenticator app.",
		Example: "  kiyesi team access kemi@example.com --role \"Frontend contractor\" --projects Storefront --until 2026-11-30\n" +
			"  kiyesi team access Bola --role client --projects \"Demo client\" --for-good",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if until != "" && !dayPattern.MatchString(until) {
				return usageErr("--until is a day, such as 2026-11-30")
			}
			if until != "" && forGood {
				return usageErr("Choose --until or --for-good, not both.")
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			team, err := c.Team(ctx)
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Changing access is for owners and admins."}
			}
			if err != nil {
				return apiErr(err)
			}
			want := strings.ToLower(strings.TrimSpace(args[0]))
			var who *api.Teammate
			for i, p := range team.People {
				first := strings.Fields(strings.ToLower(p.Name))
				if strings.ToLower(p.Name) == want || (p.Email != nil && strings.ToLower(*p.Email) == want) || (len(first) > 0 && first[0] == want) {
					if who != nil {
						return usageErr("More than one person matches %q. Give their email.", args[0])
					}
					who = &team.People[i]
				}
			}
			if who == nil {
				return usageErr("Nobody in the team is called %q. Run kiyesi team for the list.", args[0])
			}
			roleID := who.Role.ID
			if role != "" {
				if roleID, err = teamRoleID(ctx, c, role); err != nil {
					return err
				}
			}
			// Where it applies stays as it is unless --projects or
			// --leave-out says otherwise, so changing only the role or the
			// end day never widens a limited person to every project.
			scope := api.AccessScope{All: true}
			if who.Scope != nil {
				scope = *who.Scope
			}
			before := scope
			var where []string
			if projects != "" {
				list, err := c.Projects(ctx)
				if err != nil {
					return apiErr(err)
				}
				scope.All, scope.Projects = false, nil
				var names []string
				for _, name := range strings.Split(projects, ",") {
					name = strings.TrimSpace(name)
					found := false
					for _, p := range list {
						if strings.EqualFold(p.Name, name) {
							scope.Projects = append(scope.Projects, api.ProjectAccess{ProjectID: p.ID})
							names = append(names, p.Name)
							found = true
						}
					}
					if !found {
						return usageErr("There is no project called %q that you can see.", name)
					}
				}
				where = append(where, "only in "+strings.Join(names, ", "))
			}
			if leaveOut != "" {
				servers, err := c.Servers(ctx)
				if err != nil {
					return apiErr(err)
				}
				scope.LeftOut = nil
				var names []string
				for _, name := range strings.Split(leaveOut, ",") {
					s, ok := find(servers, strings.TrimSpace(name))
					if !ok {
						return usageErr("There is no server called %q that you can see.", name)
					}
					scope.LeftOut = append(scope.LeftOut, s.ID)
					names = append(names, s.Name)
				}
				where = append(where, "leaving out "+strings.Join(names, ", "))
			}
			end := until
			if until == "" && !forGood && who.EndsAt != nil {
				end = who.EndsAt.UTC().Format(time.DateOnly)
			}
			if err := c.SetAccess(ctx, who.ID, roleID, scope, end, codeOrAsk(io, code)); err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "%s's access changed. It applies on their next click.\n", who.Name)
			if len(where) > 0 && !sameScope(before, scope) {
				fmt.Fprintf(io.Out, "Where it applies changed too: %s.\n", strings.Join(where, ", "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "the role's name, such as member or \"Frontend contractor\"")
	cmd.Flags().StringVar(&projects, "projects", "", "projects it applies in, separated by commas; kept as they are when left out")
	cmd.Flags().StringVar(&leaveOut, "leave-out", "", "servers to leave out, separated by commas")
	cmd.Flags().StringVar(&until, "until", "", "the day access ends, such as 2026-11-30")
	cmd.Flags().BoolVar(&forGood, "for-good", false, "access with no end date")
	cmd.Flags().StringVar(&code, "code", "", "the code from your authenticator app, instead of typing it when asked")
	cmd.SetContext(context.Background())
	return cmd
}

// teamRoleID finds one of the team's roles, built in or made by the team,
// by its name (any case) or id.
func teamRoleID(ctx context.Context, c *api.Client, role string) (string, error) {
	roles, err := c.Roles(ctx)
	if errors.Is(err, api.ErrNotFound) {
		return "", &exitError{code: ExitUsage, msg: "Roles are for owners and admins."}
	}
	if err != nil {
		return "", apiErr(err)
	}
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
		if strings.EqualFold(r.Name, strings.TrimSpace(role)) || r.ID == role {
			return r.ID, nil
		}
	}
	sort.Strings(names)
	return "", usageErr("There is no role called %q. Roles: %s. Choose one with --role.", role, strings.Join(names, ", "))
}

// sameScope says whether two scopes give the same access.
func sameScope(a, b api.AccessScope) bool {
	a2, _ := json.Marshal(a)
	b2, _ := json.Marshal(b)
	return string(a2) == string(b2)
}

func newTeamUse(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use [team]",
		Short: "Choose which of your teams commands are for",
		Long: "Someone in several teams chooses one; commands then show only that team.\n" +
			"Without a name, lists your teams and which one is in use.",
		Example: "  kiyesi team use\n  kiyesi team use Globex",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			me, err := c.Me(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if len(args) == 0 {
				for _, t := range me.Teams {
					mark := "  "
					if t.ID == me.Team.ID {
						mark = "* "
					}
					fmt.Fprintf(io.Out, "%s%s (%s)\n", mark, t.Name, t.RoleName)
				}
				if len(me.Teams) > 1 {
					fmt.Fprintln(io.Out, "\nChoose one with: kiyesi team use <team>")
				}
				return nil
			}
			for _, t := range me.Teams {
				if strings.EqualFold(t.Name, strings.TrimSpace(args[0])) || t.ID == args[0] {
					if err := saveTeam(t.ID); err != nil {
						return err
					}
					fmt.Fprintf(io.Out, "Now using %s, as %s.\n", t.Name, t.RoleName)
					return nil
				}
			}
			names := make([]string, 0, len(me.Teams))
			for _, t := range me.Teams {
				names = append(names, t.Name)
			}
			return usageErr("You are not in a team called %q. Your teams: %s.", args[0], strings.Join(names, ", "))
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}
