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

// areaNames are the dashboard's names for the areas a role can hide.
var areaNames = map[string]string{
	"servers": "Servers", "passports": "Passports", "metrics": "Metrics", "logs": "Logs",
	"traces": "Traces", "browser_errors": "Browser errors", "databases": "Databases",
	"incidents": "Incidents", "uptime": "Uptime", "scheduled_jobs": "Scheduled jobs",
	"history": "History", "data_map": "Data map", "costs": "Costs", "reports": "Reports",
	"tips": "Tips", "settings": "Settings", "team": "Team", "credit": "Credit", "activity": "Activity",
}

// apiErr turns an API error into an exit code and a next step: 2 (usage) for
// a mistake in the command, such as a bad value, a clash or a thing that is
// not there; 3 (no access) for signed out, a role that cannot, and a service
// that cannot be reached or failed.
func apiErr(err error) error {
	if err == nil {
		return nil
	}
	var nf *api.NotFoundError
	switch {
	case errors.Is(err, api.ErrSignedOut):
		return &exitError{code: ExitNoAccess, msg: "You are signed out. Run: kiyesi login"}
	case errors.As(err, &nf) && nf.Area != "":
		// The whole area is hidden from the role: the thing may well exist.
		name, ok := areaNames[nf.Area]
		if !ok {
			name = "this"
		}
		return &exitError{code: ExitNoAccess, msg: "Your role cannot see " + name + ". Ask an owner to change your access."}
	case errors.Is(err, api.ErrNotFound):
		if nf != nil && nf.Message != "" && nf.Message != "Not found." {
			return &exitError{code: ExitUsage, msg: nf.Message}
		}
		return &exitError{code: ExitUsage, msg: "Not found."}
	}
	var p *api.Problem
	if errors.As(err, &p) {
		switch {
		case p.Code == "team_gone":
			return &exitError{code: ExitNoAccess, msg: "You are no longer in the team chosen here. Choose another with: kiyesi team use"}
		case p.Code == "two_step_required":
			return &exitError{code: ExitNoAccess, msg: "Set up two-step sign-in in the dashboard first, then run kiyesi login again."}
		case (p.Status == 400 || p.Status == 409 || p.Status == 422) && p.Message != "":
			// The service explains what is wrong with the request, in its words.
			return &exitError{code: ExitUsage, msg: p.Message}
		}
	}
	return &exitError{code: ExitNoAccess, msg: err.Error()}
}

// hiddenArea says the API hid a whole area from the person's role.
func hiddenArea(err error) bool {
	var nf *api.NotFoundError
	return errors.As(err, &nf) && nf.Area != ""
}

// freePlanNote replaces "nothing yet" where the free plan is why.
const freePlanNote = "Metrics, logs and traces are not kept on the free plan. Add credit: kiyesi credit topup"

// onFreePlan asks whether the team is on the free plan; false when it
// cannot tell, so an older service shows what it showed before.
func onFreePlan(ctx context.Context, c *api.Client) bool {
	free, err := c.FreePlan(ctx)
	return err == nil && free
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
				fmt.Fprintln(io.Out, noServers())
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "NAME\tGRADE\tCPU\tMEMORY\tDISK\tCRITICAL\tWARNINGS\tPROJECT\tSEEN")
			for _, s := range list {
				cpu, mem, disk := usage(s, time.Now())
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
			if s.Covered != nil && !*s.Covered {
				fmt.Fprintf(io.Out, "%s: %s\n%s\nAdd credit: kiyesi credit topup\n", s.Name, notWatchedTitle, notWatched)
				if d.Report == nil {
					return nil
				}
				fmt.Fprintln(io.Out, "\nThe last report it sent while it was watched:")
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

// The dashboard's words for a server the free plan does not watch.
const (
	notWatchedTitle = "Not watched on the free plan"
	notWatched      = "Without credit, Kiyesi watches one server, the first you connected. This one still says it is alive, but its scans, findings and figures are not kept until the team adds credit."
)

// noServers is what an empty list says: a filter that hides every server
// is not the same as having none.
func noServers() string {
	switch {
	case listFilter.project != "" && listFilter.env != "":
		return "No servers in that project and environment."
	case listFilter.project != "":
		return "No servers in that project."
	case listFilter.env != "":
		return "No servers in that environment."
	}
	return "No servers yet. Add one in the dashboard: Settings, Add a server."
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
	case s.Covered != nil && !*s.Covered:
		return "needs credit"
	case !s.Connected || s.LastSeenAt == nil:
		return "not connected"
	case s.Silent:
		return "silent for " + ago(now.Sub(*s.LastSeenAt))
	default:
		if d := now.Sub(*s.LastSeenAt); d < 10*time.Second {
			return "just now"
		}
		return ago(now.Sub(*s.LastSeenAt)) + " ago"
	}
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", max(0, int(d.Seconds())))
	case d < 2*time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// metricsFreshFor is how long the latest minute's figures count as "now".
const metricsFreshFor = 5 * time.Minute

// usage is the latest minute's CPU, memory and fullest disk, as percentages;
// "-" when those figures are old, or the server is disconnected or not
// watched, so old usage never reads as current.
func usage(s api.Server, now time.Time) (cpu, mem, disk string) {
	cpu, mem, disk = "-", "-", "-"
	m := s.LastMetrics
	fresh := m != nil && s.State != "disconnected" && (s.Covered == nil || *s.Covered) &&
		(m.At.IsZero() || now.Sub(m.At) <= metricsFreshFor)
	if s.MetricsFresh != nil {
		fresh = m != nil && *s.MetricsFresh
	}
	if fresh {
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
