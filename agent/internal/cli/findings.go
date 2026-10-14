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
			"matters and the fix. Kiyesi never runs a fix: copy it and run it yourself.",
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
			if len(args) == 1 {
				servers, err := c.Servers(cmd.Context())
				if err != nil {
					return apiErr(err)
				}
				s, ok := find(servers, args[0])
				if !ok {
					return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", args[0])
				}
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
				fmt.Fprintln(io.Out, "No findings: every check passed on the latest scans.")
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
				fmt.Fprintln(io.Out, "          Fix:")
				for _, line := range strings.Split(strings.TrimSpace(f.Fix), "\n") {
					fmt.Fprintf(io.Out, "            %s\n", line)
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
