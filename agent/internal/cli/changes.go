package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

// usageOr turns a refusal the service explains (a bad name, something in
// the way) into a usage error with its words; anything else as usual.
func usageOr(err error) error {
	var p *api.Problem
	if errors.As(err, &p) && (p.Status == 400 || p.Status == 409) {
		return usageErr("%s", p.Message)
	}
	return apiErr(err)
}

// projectErr explains a refused project change: without Manage on settings
// the service hides the route (not found) or refuses it, so say what it needs.
func projectErr(ctx context.Context, c *api.Client, err error) error {
	var p *api.Problem
	refused := errors.Is(err, api.ErrNotFound) || (errors.As(err, &p) && p.Status == 403 && p.Code == "not_allowed")
	if refused {
		if a, werr := c.WhoAmI(ctx); werr == nil && a.Levels["settings"] != "manage" {
			return &exitError{code: ExitNoAccess, msg: "Renaming or deleting projects needs Manage on settings. Ask an owner or admin."}
		}
	}
	return usageOr(err)
}

func findProject(ctx context.Context, c *api.Client, name string) (api.Project, error) {
	list, err := c.Projects(ctx)
	if err != nil {
		return api.Project{}, apiErr(err)
	}
	for _, p := range list {
		if strings.EqualFold(p.Name, name) {
			return p, nil
		}
	}
	return api.Project{}, usageErr("There is no project called %q that you can see. Run kiyesi projects for the list.", name)
}

func newProjects(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "projects",
		Short:   "Your projects, which group servers, checks and status pages",
		Example: "  kiyesi projects\n  kiyesi projects rename Checkout Payments\n  kiyesi projects delete Old",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Projects(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, list)
			}
			if len(list) == 0 {
				fmt.Fprint(io.Out, "No projects yet.")
				if a, err := c.WhoAmI(cmd.Context()); err == nil && a.Levels["settings"] == "manage" {
					fmt.Fprint(io.Out, " Add one in Settings, Projects.")
				}
				fmt.Fprintln(io.Out)
				return nil
			}
			for _, p := range list {
				fmt.Fprintln(io.Out, p.Name)
			}
			return nil
		},
	}
	rename := &cobra.Command{
		Use:     "rename <name> <new name>",
		Short:   "Give a project a new name",
		Example: "  kiyesi projects rename Checkout Payments",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			p, err := findProject(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if err := c.RenameProject(cmd.Context(), p.ID, args[1]); err != nil {
				return projectErr(cmd.Context(), c, err)
			}
			fmt.Fprintf(io.Out, "Renamed %s to %s.\n", p.Name, strings.TrimSpace(args[1]))
			return nil
		},
	}
	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a project once nothing is left in it",
		Long: "Deletes an empty project. While servers, checks, status pages, reports or\n" +
			"people's access are still in it, it says what is left, and deletes nothing.",
		Example: "  kiyesi projects delete Old",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			p, err := findProject(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			uses, err := c.ProjectUses(cmd.Context(), p.ID)
			if err != nil {
				return projectErr(cmd.Context(), c, err)
			}
			if len(uses) > 0 {
				fmt.Fprintf(io.Out, "%s still has:\n", p.Name)
				for _, u := range uses {
					word := u.Many
					if u.Count == 1 {
						word = u.One
					}
					fmt.Fprintf(io.Out, "  %d %s\n", u.Count, word)
				}
				return usageErr("move or remove them first; nothing was deleted")
			}
			if err := c.DeleteProject(cmd.Context(), p.ID); err != nil {
				return projectErr(cmd.Context(), c, err)
			}
			fmt.Fprintf(io.Out, "Deleted the project %s.\n", p.Name)
			return nil
		},
	}
	cmd.AddCommand(rename, del)
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}

func newUptimeEdit(io IO) *cobra.Command {
	var name, address, project, env string
	cmd := &cobra.Command{
		Use:   "edit <name or address>",
		Short: "Change a check's name, address or project; its history stays",
		Example: "  kiyesi uptime edit Shop --address https://shop.example.com/health\n" +
			"  kiyesi uptime edit Shop --name \"Shop health\" --project Checkout",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			change := map[string]any{}
			if name != "" {
				change["name"] = name
			}
			if address != "" {
				change["url"] = address
			}
			if env != "" && env != "production" && env != "staging" {
				return usageErr("--env is production or staging")
			}
			if name == "" && address == "" && project == "" && env == "" {
				return usageErr("say what to change: --name, --address, --project or --env")
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			if project != "" {
				p, err := findProject(cmd.Context(), c, project)
				if err != nil {
					return err
				}
				change["projectId"] = p.ID
			}
			if env != "" {
				change["environment"] = env
			}
			checks, err := c.Uptime(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			var target *api.UptimeCheck
			for i := range checks {
				if strings.EqualFold(checks[i].Name, args[0]) || checks[i].URL == args[0] {
					target = &checks[i]
				}
			}
			if target == nil {
				return usageErr("There is no uptime check called %q. Run kiyesi uptime for the list.", args[0])
			}
			if err := c.EditUptime(cmd.Context(), target.ID, change); err != nil {
				return usageOr(err)
			}
			fmt.Fprintf(io.Out, "Changed the check %s. Its history stays.\n", target.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "a new name")
	cmd.Flags().StringVar(&address, "address", "", "a new address to check")
	cmd.Flags().StringVar(&project, "project", "", "move it to this project")
	cmd.Flags().StringVar(&env, "env", "", "production or staging, with --project")
	return cmd
}

func newServersRename(io IO) *cobra.Command {
	return &cobra.Command{
		Use:     "rename <name> <new name>",
		Short:   "Give a server a new name; its agent and token are unchanged",
		Example: "  kiyesi servers rename web-1 checkout-web",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			s, err := visibleServer(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if strings.TrimSpace(args[1]) == s.Name {
				fmt.Fprintf(io.Out, "%s is already called that.\n", s.Name)
				return nil
			}
			if err := c.RenameServer(cmd.Context(), s.ID, args[1]); err != nil {
				return usageOr(err)
			}
			fmt.Fprintf(io.Out, "Renamed %s to %s.\n", s.Name, strings.TrimSpace(args[1]))
			return nil
		},
	}
}

func newDeploysRemove(io IO) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <app> <version>",
		Short: "Remove a deploy marked by mistake, with its History lines",
		Long: "Removes the deploy marker, its verdict, its lines in History and a roll-back\n" +
			"alert it raised. The activity log keeps that you removed it.",
		Example: "  kiyesi deploys remove checkout-api 3.8.1-oops",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Deploys(cmd.Context(), "90d")
			if err != nil {
				return apiErr(err)
			}
			for _, d := range list {
				if d.App == args[0] && d.Version == args[1] {
					if err := c.RemoveDeploy(cmd.Context(), d.ID); err != nil {
						return usageOr(err)
					}
					fmt.Fprintf(io.Out, "Removed the deploy %s %s of %s.\n", d.App, d.Version, d.At.Local().Format("2 Jan 15:04"))
					return nil
				}
			}
			return usageErr("There is no deploy of %s %s in the last 90 days. Run kiyesi deploys --since 90d for the list.", args[0], args[1])
		},
	}
}

func newTeamLeave(io IO) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "leave",
		Short: "Leave the team these commands are for",
		Long: "Your open work goes back to Unassigned, and you need a new invite to come back.\n" +
			"A team's only owner makes someone else an owner first.",
		Example: "  kiyesi team leave",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			// Name the team first: someone in several may not know which this is.
			me, err := c.Me(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			team := me.Team.Name
			if team == "" {
				team = "this team"
			}
			if !yes && !strings.EqualFold(strings.TrimSpace(ask(io, "Leave "+team+"? Type yes: ")), "yes") {
				return usageErr("nothing changed")
			}
			if err := c.LeaveTeam(cmd.Context()); err != nil {
				var p *api.Problem
				if errors.As(err, &p) && p.Status == 403 {
					return &exitError{code: ExitNoAccess, msg: p.Message}
				}
				return apiErr(err)
			}
			// The team chosen here is gone: commands go back to the oldest team.
			if c.TeamID != "" && c.TeamID == me.Team.ID {
				_ = saveTeam("")
			}
			fmt.Fprintf(io.Out, "You left %s. Your open work went back to Unassigned.\n", team)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask first")
	return cmd
}

func newSessions(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "sessions",
		Short:   "Where you are signed in: each browser and kiyesi command",
		Example: "  kiyesi sessions\n  kiyesi sessions end 2\n  kiyesi sessions end --others",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Sessions(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, list)
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			// The service refreshes a session about once a day of use, so
			// this is when it was last refreshed, not the last request.
			fmt.Fprintln(tw, "#\tDEVICE\tLAST REFRESHED\tFROM")
			for i, s := range list {
				device := s.Device
				if s.Current {
					device += " (this one)"
				}
				from := "unknown"
				if s.Address != nil {
					from = *s.Address
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", i+1, device, s.LastUsedAt.Local().Format("2 Jan 15:04"), from)
			}
			return tw.Flush()
		},
	}
	var others bool
	end := &cobra.Command{
		Use:     "end <number>",
		Short:   "Sign out one session, by its number in kiyesi sessions, or every other",
		Example: "  kiyesi sessions end 2\n  kiyesi sessions end --others",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			if others {
				n, err := c.EndOtherSessions(cmd.Context())
				if err != nil {
					return apiErr(err)
				}
				if n == 0 {
					fmt.Fprintln(io.Out, "No other sessions.")
					return nil
				}
				fmt.Fprintf(io.Out, "Signed out everywhere else: %s.\n", plural(n, "session", "sessions"))
				return nil
			}
			if len(args) != 1 {
				return usageErr("give the session's number from kiyesi sessions, or --others")
			}
			n, err := strconv.Atoi(args[0])
			list, lerr := c.Sessions(cmd.Context())
			if lerr != nil {
				return apiErr(lerr)
			}
			if err != nil || n < 1 || n > len(list) {
				return usageErr("there is no session %s: run kiyesi sessions for the numbers", args[0])
			}
			s := list[n-1]
			if s.Current {
				return usageErr("that is this one: use kiyesi logout")
			}
			if err := c.EndSession(cmd.Context(), s.ID); err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "Signed out %s.\n", s.Device)
			return nil
		},
	}
	end.Flags().BoolVar(&others, "others", false, "every session but this one")
	cmd.AddCommand(end)
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}
