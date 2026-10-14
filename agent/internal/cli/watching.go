package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// deployClient picks how kiyesi deploy signs in: a deploy token from
// KIYESI_DEPLOY_TOKEN (for CI), this server's own token when it is
// connected, or the person signed in with kiyesi login.
func deployClient(apiURL string, environ []string) (*api.Client, string, error) {
	env := envMap(environ)
	if t := strings.TrimSpace(env["KIYESI_DEPLOY_TOKEN"]); t != "" {
		if !strings.HasPrefix(t, "kdp_") {
			return nil, "", usageErr("KIYESI_DEPLOY_TOKEN is not a deploy token. Make one in the dashboard: Settings, Deploy tokens.")
		}
		return api.New(apiURL, t), "deploy token", nil
	}
	if conf, token, err := loadConnection(); err == nil {
		return api.New(conf.API, token), "this server", nil
	}
	c, err := signedIn()
	if err != nil {
		return nil, "", &exitError{code: ExitNoAccess, msg: "Set KIYESI_DEPLOY_TOKEN (Settings, Deploy tokens), run this on a connected server, or sign in with kiyesi login."}
	}
	return c, "you", nil
}

func envMap(environ []string) map[string]string {
	m := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// gitAuthor reads the latest commit's author. Tests replace it.
var gitAuthor = func() string {
	path, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	out, err := exec.Command(path, "log", "-1", "--format=%an").Output() // #nosec G204 -- the system's git, fixed arguments
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// shippedBy is who shipped a deploy: the CI system's user, then the latest
// commit's author, then the user running the command.
func shippedBy(environ []string) string {
	env := envMap(environ)
	for _, k := range []string{"GITHUB_ACTOR", "GITLAB_USER_LOGIN", "BITBUCKET_STEP_TRIGGERER_UUID", "CIRCLE_USERNAME", "BUILDKITE_BUILD_CREATOR", "DRONE_COMMIT_AUTHOR"} {
		if v := strings.TrimSpace(env[k]); v != "" {
			return v
		}
	}
	if a := gitAuthor(); a != "" {
		return a
	}
	return env["USER"]
}

func newDeploy(io IO) *cobra.Command {
	var d api.Deploy
	var apiURL string
	cmd := &cobra.Command{
		Use:   "deploy --app <name> --version <version>",
		Short: "Mark a deploy, from your deploy script, so charts and History show it",
		Long: "Records that a version of an app was deployed, and who shipped it. Run it at the\n" +
			"end of a deploy. In CI, set KIYESI_DEPLOY_TOKEN; on a connected server it uses\n" +
			"the server's own token; on a laptop, sign in with kiyesi login first.",
		Example: "  kiyesi deploy --app checkout-api --version 3.8.1\n" +
			"  KIYESI_DEPLOY_TOKEN=kdp_... kiyesi deploy --app web --version $GIT_SHA --server web-prod",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(d.App) == "" || strings.TrimSpace(d.Version) == "" {
				return usageErr("Give the app and its version: kiyesi deploy --app checkout-api --version 3.8.1")
			}
			c, how, err := deployClient(apiURL, io.Environ)
			if err != nil {
				return err
			}
			if d.By == "" {
				d.By = shippedBy(io.Environ)
			}
			if err := c.MarkDeploy(cmd.Context(), d); err != nil {
				var p *api.Problem
				if errors.As(err, &p) && p.Status == 400 {
					return usageErr("%s", p.Message)
				}
				return apiErr(err)
			}
			where := d.Server
			if where == "" && how == "this server" {
				where = "this server"
			}
			fmt.Fprintf(io.Out, "Marked: %s %s", d.App, d.Version)
			if where != "" {
				fmt.Fprintf(io.Out, " on %s", where)
			}
			if d.By != "" {
				fmt.Fprintf(io.Out, ", by %s", d.By)
			}
			fmt.Fprintln(io.Out, ".")
			return nil
		},
	}
	cmd.Flags().StringVar(&d.App, "app", "", "the app that was deployed")
	cmd.Flags().StringVar(&d.Version, "version", "", "its version, tag or commit")
	cmd.Flags().StringVar(&d.Server, "server", "", "the server it went to (needed with a deploy token or kiyesi login)")
	cmd.Flags().StringVar(&d.Project, "project", "", "the project, when it went to several servers")
	cmd.Flags().StringVar(&d.Environment, "env", "", "production or staging, with --project")
	cmd.Flags().StringVar(&d.By, "by", "", "who shipped it (default: the CI user, then the last commit's author)")
	cmd.Flags().StringVar(&apiURL, "api", envOr("KIYESI_API", DefaultAPI), "the service address, with a deploy token")
	cmd.SetContext(context.Background())
	return cmd
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newDeploys(io IO) *cobra.Command {
	var since, server string
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "deploys",
		Short:   "Recent deploys with their verdict: healthy or roll back",
		Long:    "Each deploy is watched for 10 minutes after it goes out, then judged healthy\nor roll back, with the evidence and the roll-back command.",
		Example: "  kiyesi deploys --since 7d\n  kiyesi deploys --server checkout-api-prod",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rng := map[string]string{"24h": "24h", "1d": "24h", "today": "24h", "yesterday": "24h", "7d": "7d", "week": "7d", "30d": "30d", "90d": "90d"}[strings.ToLower(since)]
			if rng == "" {
				return usageErr("--since must be 24h, 7d, 30d or 90d, not %q", since)
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Deploys(cmd.Context(), rng)
			if err != nil {
				return apiErr(err)
			}
			var shown []api.DeployVerdict
			for _, d := range list {
				if server == "" || (d.Server != nil && strings.EqualFold(d.Server.Name, server)) {
					shown = append(shown, d)
				}
			}
			if asJSON {
				return render.JSON(io.Out, shown)
			}
			if len(shown) == 0 {
				fmt.Fprintln(io.Out, "No deploys marked in that time. Add kiyesi deploy to your deploy script.")
				return nil
			}
			words := map[string]string{"watching": "watching", "healthy": "healthy", "roll_back": "ROLL BACK", "unknown": "not enough to judge"}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "WHEN\tAPP\tVERSION\tBY\tWHERE\tVERDICT")
			for _, d := range shown {
				by, where := "-", "-"
				if d.By != nil {
					by = *d.By
				}
				if d.Server != nil {
					where = d.Server.Name
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.At.Local().Format("Mon 2 Jan 15:04"), d.App, d.Version, by, where, words[d.Status])
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if d := shown[0]; d.Sentence != nil {
				fmt.Fprintf(io.Out, "\nLatest: %s %s, %s. %s\n", d.App, d.Version, words[d.Status], *d.Sentence)
				if d.Status == "roll_back" && d.Rollback != nil {
					fmt.Fprintf(io.Out, "\n  %s\n", *d.Rollback)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "how far back: 24h, 7d, 30d or 90d")
	cmd.Flags().StringVar(&server, "server", "", "only this server")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	cmd.AddCommand(newDeploysRemove(io))
	return cmd
}

func newHistory(io IO) *cobra.Command {
	var since, server string
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "history",
		Short:   "Deploys, findings, grade changes, restarts and outages, in time order",
		Example: "  kiyesi history --since yesterday\n  kiyesi history --server checkout-api-prod --since 7d",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printHistory(cmd.Context(), io, since, server, "", "Nothing happened in that time.", asJSON)
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "how far back: 1h, 24h (or yesterday), 7d, 30d or 90d")
	cmd.Flags().StringVar(&server, "server", "", "only this server")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

var sinceNames = map[string]string{"yesterday": "24h", "today": "24h", "1h": "1h", "24h": "24h", "1d": "24h", "7d": "7d", "week": "7d", "30d": "30d", "90d": "90d"}

func printHistory(ctx context.Context, io IO, since, server, kinds, empty string, asJSON bool) error {
	s, ok := sinceNames[strings.ToLower(since)]
	if !ok {
		return usageErr("--since must be 1h, 24h, yesterday, 7d, 30d or 90d, not %q", since)
	}
	c, err := signedIn()
	if err != nil {
		return err
	}
	serverID := ""
	if server != "" {
		list, err := c.Servers(ctx)
		if err != nil {
			return apiErr(err)
		}
		found, ok := find(list, server)
		if !ok {
			return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", server)
		}
		serverID = found.ID
	}
	events, err := c.History(ctx, s, serverID, kinds)
	if err != nil {
		return apiErr(err)
	}
	if asJSON {
		return jsonOut(io.Out, events)
	}
	if len(events) == 0 {
		fmt.Fprintln(io.Out, empty)
		return nil
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		fmt.Fprintf(io.Out, "%s  %s\n", e.At.Local().Format("Mon 2 Jan 15:04"), e.Title)
	}
	return nil
}

func newMetrics(io IO) *cobra.Command {
	var since string
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "metrics <server>",
		Short:   "CPU, memory, disk and requests over time, drawn in the terminal",
		Example: "  kiyesi metrics checkout-api-prod --since 24h",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := map[string]string{"1h": "1h", "24h": "24h", "yesterday": "24h", "7d": "7d", "30d": "30d"}[strings.ToLower(since)]
			if r == "" {
				return usageErr("--since must be 1h, 24h, 7d or 30d, not %q", since)
			}
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
			ch, err := c.Metrics(cmd.Context(), s.ID, r)
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, ch)
			}
			drawCharts(io.Out, s.Name, r, ch)
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "how far back: 1h, 24h, 7d or 30d")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the numbers as JSON")
	cmd.SetContext(context.Background())
	return cmd
}

const sparkWidth = 48

// spark draws values as a row of bars, resampled to the width.
func spark(points [][2]float64, top float64) string {
	if len(points) == 0 {
		return strings.Repeat(" ", sparkWidth)
	}
	bars := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for i := 0; i < sparkWidth; i++ {
		lo := i * len(points) / sparkWidth
		hi := max(lo+1, (i+1)*len(points)/sparkWidth)
		v := 0.0
		for _, p := range points[lo:min(hi, len(points))] {
			v = math.Max(v, p[1])
		}
		if top <= 0 {
			b.WriteRune(bars[0])
			continue
		}
		b.WriteRune(bars[min(len(bars)-1, int(v/top*float64(len(bars)-1)+0.5))])
	}
	return b.String()
}

func stats(points [][2]float64) (now, peak float64) {
	for _, p := range points {
		peak = math.Max(peak, p[1])
	}
	if len(points) > 0 {
		now = points[len(points)-1][1]
	}
	return now, peak
}

func drawCharts(w io.Writer, name, r string, ch api.Charts) {
	fmt.Fprintf(w, "\n%s, last %s\n\n", name, r)
	row := func(label string, points [][2]float64, top float64, unit string) {
		if len(points) == 0 {
			fmt.Fprintf(w, "%-9s no data yet\n", label)
			return
		}
		now, peak := stats(points)
		fmt.Fprintf(w, "%-9s %s  now %s%s  peak %s%s\n", label, spark(points, top), num(now), unit, num(peak), unit)
	}
	row("CPU", ch.CPU, 100, "%")
	row("Memory", ch.Memory, 100, "%")
	mounts := make([]string, 0, len(ch.Disk))
	for m := range ch.Disk {
		mounts = append(mounts, m)
	}
	sort.Strings(mounts)
	for _, m := range mounts {
		row("Disk "+m, ch.Disk[m], 100, "%")
	}
	_, peakReq := stats(ch.Requests)
	if len(ch.Requests) > 0 {
		row("Requests", ch.Requests, peakReq, "/min")
		_, peakErr := stats(ch.Errors)
		row("Failed", ch.Errors, math.Max(peakErr, 1), "/min")
		_, peakP95 := stats(ch.P95)
		row("Slowest", ch.P95, peakP95, " ms")
	} else {
		fmt.Fprintln(w, "Requests  none read yet: Kiyesi reads nginx's access log, or an nginx or Caddy container's output")
	}
	if len(ch.Deploys) > 0 {
		fmt.Fprintln(w, "\nDeploys")
		for i := len(ch.Deploys) - 1; i >= 0; i-- {
			d := ch.Deploys[i]
			fmt.Fprintf(w, "  %s  %s\n", d.At.Local().Format("Mon 2 Jan 15:04"), d.Title)
		}
	}
	fmt.Fprintln(w)
}

func num(v float64) string {
	if v >= 100 || v == math.Trunc(v) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}
