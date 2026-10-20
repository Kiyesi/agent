package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// openPages are the dashboard's screens that `kiyesi open <name>` knows.
var openPages = map[string]string{
	"servers": "/servers/", "incidents": "/incidents/", "work": "/work/", "metrics": "/metrics/",
	"logs": "/logs/", "traces": "/traces/", "errors": "/browser-errors/", "alerts": "/alerts/",
	"uptime": "/uptime/", "history": "/history/", "jobs": "/jobs/", "databases": "/databases/",
	"costs": "/costs/", "datamap": "/data-map/", "tips": "/tips/", "reports": "/reports/",
	"team": "/team/", "roles": "/roles/", "settings": "/settings/", "credit": "/credit/",
}

// dashboardURL is the dashboard beside the API the person signed in to:
// https://api.kiyesi.dev serves https://app.kiyesi.dev. KIYESI_DASHBOARD overrides it.
func dashboardURL(api string) string {
	if d := os.Getenv("KIYESI_DASHBOARD"); d != "" {
		return strings.TrimRight(d, "/")
	}
	u, err := url.Parse(api)
	if err != nil || u.Host == "" {
		return "https://app.kiyesi.dev"
	}
	if rest, ok := strings.CutPrefix(u.Host, "api."); ok {
		u.Host = "app." + rest
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/")
}

// openPage opens a dashboard address in the browser, and always prints it,
// since a server has no browser.
func openPage(io IO, address string) {
	fmt.Fprintln(io.Out, address)
	openBrowser(address)
}

// withTeam adds the chosen team to a dashboard page's address; the
// dashboard switches to it only when the person is in that team.
func withTeam(page, team string) string {
	if team == "" {
		return page
	}
	sep := "?"
	if strings.Contains(page, "?") {
		sep = "&"
	}
	return page + sep + "team=" + url.QueryEscape(team)
}

func newOpen(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open [incident, server or screen]",
		Short: "Open the matching dashboard page in the browser",
		Long: "With an incident number (INC-12), a server's name, or a screen such as\n" +
			"logs or credit; alone, the dashboard's home. The address is printed too.",
		Example: "  kiyesi open INC-12\n  kiyesi open checkout-api-prod\n  kiyesi open credit",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loadLogin()
			if err != nil {
				return err
			}
			base := dashboardURL(l.API)
			// The team chosen with kiyesi team use goes with the address, so
			// the dashboard shows that team's page, not the one it last showed.
			open := func(page string) {
				openPage(io, base+withTeam(page, l.Team))
			}
			if len(args) == 0 {
				open("/")
				return nil
			}
			what := args[0]
			if p, ok := openPages[strings.ToLower(what)]; ok {
				open(p)
				return nil
			}
			if incidentRef.MatchString(what) {
				ref := strings.ToUpper(what)
				if !strings.HasPrefix(ref, "INC-") {
					ref = "INC-" + ref
				}
				open("/incident/?id=" + url.QueryEscape(ref))
				return nil
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			servers, err := c.Servers(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if s, ok := find(servers, what); ok {
				open("/server/?id=" + url.QueryEscape(s.ID))
				return nil
			}
			return usageErr("Nothing called %q: give an incident number such as INC-12, a server's name, or a screen such as logs, incidents or credit.", what)
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}
