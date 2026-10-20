package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// thisServer is the connected server's id and API, when this machine is one,
// from its settings (no token is read: a server's token can only send results).
var thisServer = func() agentConf {
	var conf agentConf
	if data, err := os.ReadFile(agentConfPath()); err == nil { // #nosec G304 -- kiyesi's own settings file
		_ = yaml.Unmarshal(data, &conf)
	}
	return conf
}

func newPreflight(io IO) *cobra.Command {
	var asJSON bool
	var apiURL string
	cmd := &cobra.Command{
		Use:   "preflight [server]",
		Short: "Safe to deploy? Go or wait, with the reasons and what to do first",
		Long: "Six checks on what Kiyesi already holds for the server: memory, disk, backup\n" +
			"age, certificate, open incidents on it, and the last deploy's verdict. It\n" +
			"exits with 0 for go and 1 for wait, so a deploy pipeline can use it. It only\n" +
			"advises and never stops a deploy by itself. In CI, set KIYESI_DEPLOY_TOKEN.\n" +
			"A server that sent no figures in the last 5 minutes is a reason to wait.",
		Example: "  kiyesi preflight checkout-api-prod\n  kiyesi preflight              on a connected server: this one\n  kiyesi preflight checkout-api-prod --json",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			here := thisServer()
			server := here.ServerID
			if len(args) == 1 {
				server = args[0]
			}
			if server == "" {
				return usageErr("Name the server: kiyesi preflight checkout-api-prod. Run kiyesi servers for the list.")
			}
			var c *api.Client
			if t := strings.TrimSpace(envMap(io.Environ)["KIYESI_DEPLOY_TOKEN"]); t != "" {
				if !strings.HasPrefix(t, "kdp_") {
					return usageErr("KIYESI_DEPLOY_TOKEN is not a deploy token. Make one in the dashboard: Settings, Deploy tokens.")
				}
				if !cmd.Flags().Changed("api") && here.API != "" {
					apiURL = here.API
				}
				c = api.New(apiURL, t)
			} else {
				var err error
				if c, err = signedIn(); err != nil {
					return &exitError{code: ExitNoAccess, msg: "Set KIYESI_DEPLOY_TOKEN (Settings, Deploy tokens), or sign in with kiyesi login."}
				}
			}
			p, err := c.Preflight(cmd.Context(), server)
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				if err := render.JSON(io.Out, p); err != nil {
					return err
				}
			} else {
				printPreflight(io, p)
			}
			if p.Answer == "wait" {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.Flags().StringVar(&apiURL, "api", "https://api.kiyesi.dev", "the Kiyesi API, with a deploy token")
	cmd.SetContext(context.Background())
	return cmd
}

func printPreflight(io IO, p api.Preflight) {
	w := render.NewWriter(io.Out, io.Environ)
	place := p.Server.Name
	if p.Server.Project != nil {
		place += " · " + p.Server.Project.Name
	}
	if p.Server.Environment != nil {
		place += " · " + strings.ToUpper((*p.Server.Environment)[:1]) + (*p.Server.Environment)[1:]
	}
	fmt.Fprintf(w, "Kiyesi %s · safe to deploy? · %d checks\n%s\n", version.Version, len(p.Checks), place)
	// How old the scan behind the backup and certificate checks is.
	if p.ScannedAt != nil {
		fmt.Fprintf(w, "Last scan: %s ago, %s.\n\n", ago(time.Since(*p.ScannedAt)), p.ScannedAt.UTC().Format("2 January 2006 15:04 UTC"))
	} else {
		fmt.Fprint(w, "No scan yet.\n\n")
	}
	words := map[string]string{"pass": "PASS", "wait": "WAIT", "unknown": "  ? "}
	colour := map[string]string{"pass": "\x1b[32m", "wait": "\x1b[1;33m", "unknown": "\x1b[2m"}
	// Reasons to wait first, then what is not known, then what passed.
	for _, status := range []string{"wait", "unknown", "pass"} {
		for _, c := range p.Checks {
			if c.Status == status {
				fmt.Fprintf(w, " %s%s\x1b[0m  %-14s %s\n", colour[status], words[status], c.Label, c.Sentence)
			}
		}
	}
	if p.Answer == "wait" {
		fmt.Fprintf(w, "\nANSWER  \x1b[1;33mWAIT\x1b[0m  %s\n\nDO FIRST\n", plural(len(p.DoFirst), "reason", "reasons"))
		for i, d := range p.DoFirst {
			fmt.Fprintf(w, " %d. %s\n", i+1, d)
		}
	} else {
		fmt.Fprint(w, "\nANSWER  \x1b[1;32mGO\x1b[0m\n")
	}
	fmt.Fprint(w, "\nThis command only advises. It never stops a deploy by itself.\nIn a pipeline it exits with 0 for GO and 1 for WAIT.\n")
}
