package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func newFindings(io IO) *cobra.Command {
	var asJSON bool
	var severity string
	cmd := &cobra.Command{
		Use:   "findings [server]",
		Short: "Every finding on your servers, worst first, with the command that fixes it",
		Long: "The problems the latest scans found, each in one sentence with why it\n" +
			"matters and the fix. The agent never runs a fix by itself: run sudo kiyesi fix\n" +
			"on the server where one is offered, or run the command yourself.",
		Example: "  kiyesi findings\n  kiyesi findings checkout-api-prod --severity critical",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if severity != "" && severity != "critical" && severity != "warning" && severity != "info" {
				return usageErr("--severity must be critical, warning or info, not %q.", severity)
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Findings(cmd.Context(), severity)
			if err != nil {
				return apiErr(err)
			}
			var servers []api.Server
			if len(args) == 1 {
				all, err := c.Servers(cmd.Context())
				if err != nil {
					return apiErr(err)
				}
				s, ok := find(all, args[0])
				if !ok {
					return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", args[0])
				}
				servers = []api.Server{s}
				kept := list[:0]
				for _, f := range list {
					if f.Server.ID == s.ID {
						kept = append(kept, f)
					}
				}
				list = kept
			}
			if asJSON {
				if list == nil {
					list = []api.Finding{}
				}
				return render.JSON(io.Out, list)
			}
			if len(list) == 0 {
				if servers == nil {
					if servers, err = c.Servers(cmd.Context()); err != nil {
						return apiErr(err)
					}
				}
				fmt.Fprintln(io.Out, noFindings(servers, severity, len(args) == 1))
				return nil
			}
			for i, f := range list {
				if i > 0 {
					fmt.Fprintln(io.Out)
				}
				label := map[string]string{"critical": "CRITICAL", "warning": "WARNING", "info": "INFO"}[f.Severity]
				likely := ""
				if f.Confidence != nil && *f.Confidence == "likely" {
					likely = " · likely"
				}
				fmt.Fprintf(io.Out, "%-8s  %s%s\n          %s · %s\n          %s\n", label, f.Sentence, likely, f.Server.Name, f.CheckName, f.Why)
				first, byHand := render.FixLines(strings.TrimSpace(f.Fix), autoFixOf(f.AutoFix))
				fmt.Fprintln(io.Out, "          Fix:")
				for _, line := range strings.Split(first, "\n") {
					fmt.Fprintf(io.Out, "            %s\n", line)
				}
				if byHand != "" {
					fmt.Fprintln(io.Out, "          By hand:")
					for _, line := range strings.Split(byHand, "\n") {
						fmt.Fprintf(io.Out, "            %s\n", line)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.Flags().StringVar(&severity, "severity", "", "only critical, warning or info")
	cmd.SetContext(context.Background())
	return cmd
}

// noFindings says truthfully why the list is empty: no servers, only
// managed services (never scanned), no scan yet, a --severity that hides
// the rest, or every check passed.
func noFindings(servers []api.Server, severity string, named bool) string {
	if len(servers) == 0 {
		return noServers()
	}
	var agents, scanned []api.Server
	for _, s := range servers {
		if s.Kind == "managed" {
			continue
		}
		agents = append(agents, s)
		if s.LastScan != nil {
			scanned = append(scanned, s)
		}
	}
	switch {
	case len(agents) == 0 && named:
		return servers[0].Name + " is a managed service: Kiyesi does not scan it, so it has no findings."
	case len(agents) == 0:
		return "Only managed services here: Kiyesi does not scan them, so there are no findings. Findings come from servers with the agent."
	case len(scanned) == 0 && named:
		return agents[0].Name + " has not sent a scan yet, so there are no findings yet."
	case len(scanned) == 0:
		return "No server has sent a scan yet, so there are no findings yet."
	}
	if severity != "" {
		others := 0
		for _, s := range scanned {
			others += s.LastScan.Counts.Critical + s.LastScan.Counts.Warnings
		}
		if others > 0 {
			return fmt.Sprintf("No %s findings on the latest scans. Run kiyesi findings without --severity for the rest.", severity)
		}
		return fmt.Sprintf("No %s findings on the latest scans.", severity)
	}
	if waiting := len(agents) - len(scanned); waiting > 0 {
		return fmt.Sprintf("No findings on the latest scans. %s not sent a scan yet.", plural(waiting, "server has", "servers have"))
	}
	return "No findings: every check passed on the latest scans."
}

// autoFixOf is the kiyesi fix a finding names, or "" when it names none.
func autoFixOf(name *string) string {
	if name == nil {
		return ""
	}
	return *name
}
