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

// signedIn returns a client for the signed-in person.
func signedIn() (*api.Client, error) {
	l, err := loadLogin()
	if err != nil {
		return nil, err
	}
	c := api.New(l.API, l.Token)
	c.TeamID = l.Team
	c.Project, c.Env = listFilter.project, listFilter.env
	return c, nil
}

// listFilter is --project and --env, which narrow any list (PRD rule 2).
var listFilter struct{ project, env string }

// apiErr turns an API error into an exit code and a next step.
func apiErr(err error) error {
	switch {
	case errors.Is(err, api.ErrSignedOut):
		return &exitError{code: ExitNoAccess, msg: "You are signed out. Run: kiyesi login"}
	case errors.Is(err, api.ErrNotFound):
		var nf *api.NotFoundError
		if errors.As(err, &nf) && nf.Message != "" && nf.Message != "Not found." {
			return &exitError{code: ExitUsage, msg: nf.Message}
		}
		return &exitError{code: ExitUsage, msg: "Not found."}
	}
	var p *api.Problem
	if errors.As(err, &p) && p.Code == "team_gone" {
		return &exitError{code: ExitNoAccess, msg: "You are no longer in the team chosen here. Choose another with: kiyesi team use"}
	}
	if errors.As(err, &p) && p.Code == "two_step_required" {
		return &exitError{code: ExitNoAccess, msg: "Set up two-step sign-in in the dashboard first, then run kiyesi login again."}
	}
	return &exitError{code: ExitNoAccess, msg: err.Error()}
}

func newServers(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "servers",
		Short:   "List your servers, worst first",
		Example: "  kiyesi servers\n  kiyesi servers --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Servers(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, list)
			}
			if len(list) == 0 {
				fmt.Fprintln(io.Out, "No servers yet. Add one in the dashboard: Settings, Add a server.")
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "NAME\tGRADE\tCPU\tMEMORY\tDISK\tCRITICAL\tWARNINGS\tPROJECT\tSEEN")
			for _, s := range list {
				cpu, mem, disk := usage(s)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, grade(s), cpu, mem, disk, count(s, true), count(s, false), place(s), seen(s, time.Now()))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.AddCommand(newServersDisconnect(io), newServersDelete(io), newServersRestore(io), newServersReconnect(io), newServersRename(io))
	cmd.SetContext(context.Background())
	return cmd
}

func newServer(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "server <name>",
		Short:   "Show a server's latest report: grade, problems and fixes",
		Example: "  kiyesi server checkout-api-prod",
		Args:    cobra.ExactArgs(1),
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
			d, err := c.Server(cmd.Context(), s.ID)
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, d)
			}
			if d.Report == nil {
				fmt.Fprintf(io.Out, "%s has not sent a scan yet. Once it is connected, the first one arrives within a minute.\n", s.Name)
				return nil
			}
			return render.Stored(render.NewWriter(io.Out, io.Environ), *d.Report, s.Name)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the server and its full report as JSON")
	cmd.SetContext(context.Background())
	return cmd
}

// find matches a server by its exact name, then ignoring case.
func find(list []api.Server, name string) (api.Server, bool) {
	for _, s := range list {
		if s.Name == name {
			return s, true
		}
	}
	for _, s := range list {
		if strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return api.Server{}, false
}

func grade(s api.Server) string {
	if s.LastScan == nil {
		return "-"
	}
	return fmt.Sprintf("%s %d", s.LastScan.Grade.Letter, s.LastScan.Grade.Score)
}

func count(s api.Server, critical bool) string {
	if s.LastScan == nil {
		return "-"
	}
	if critical {
		return fmt.Sprint(s.LastScan.Counts.Critical)
	}
	return fmt.Sprint(s.LastScan.Counts.Warnings)
}

func place(s api.Server) string {
	if s.Project == nil {
		return "-"
	}
	return s.Project.Name + " · " + s.Environment
}

func seen(s api.Server, now time.Time) string {
	switch {
	case s.State == "disconnected":
		return "disconnected"
	case !s.Connected || s.LastSeenAt == nil:
		return "not connected"
	case s.Silent:
		return "silent for " + ago(now.Sub(*s.LastSeenAt))
	default:
		return ago(now.Sub(*s.LastSeenAt)) + " ago"
	}
}

func ago(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < 2*time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// usage is the latest minute's CPU, memory and fullest disk, as percentages.
func usage(s api.Server) (cpu, mem, disk string) {
	cpu, mem, disk = "-", "-", "-"
	if m := s.LastMetrics; m != nil {
		f := func(v *float64) string {
			if v == nil {
				return "-"
			}
			return fmt.Sprintf("%.0f%%", *v)
		}
		cpu, mem, disk = f(m.CPU), f(m.Memory), f(m.Disk)
	}
	return cpu, mem, disk
}
