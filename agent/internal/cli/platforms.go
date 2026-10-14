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
)

var platformNames = map[string]string{
	"render": "Render", "heroku": "Heroku", "railway": "Railway", "fly": "Fly.io",
	"vercel": "Vercel", "netlify": "Netlify", "other": "Other",
}

func newPlatforms(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "platforms",
		Short: "List the managed platforms linked, and the services each one sends",
		Long: "Apps on Render, Heroku, Railway, Fly.io, Vercel, Netlify or anywhere else report\n" +
			"through a platform link made in Settings, Managed services. Each service a\n" +
			"platform names is its own server, with no scan: the platform runs the machine.",
		Example: "  kiyesi platforms",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			links, err := c.PlatformLinks(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Your role cannot see servers."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, links)
			}
			if len(links) == 0 {
				fmt.Fprintln(io.Out, "No platform is linked. Link one in Settings, Managed services.")
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "LINK\tPLATFORM\tWHERE\tLAST SENT\tSERVICES\tWAITING")
			for _, l := range links {
				last := "never"
				if l.LastSeenAt != nil {
					last = humanAgo(time.Since(*l.LastSeenAt))
				}
				var names []string
				for _, s := range l.Services {
					n := s.Name
					if s.State == "disconnected" {
						n += " (off)"
					}
					names = append(names, n)
				}
				name := platformNames[l.Platform]
				if name == "" {
					name = l.Platform
				}
				fmt.Fprintf(tw, "%s\t%s\t%s %s\t%s\t%s\t%s\n", l.Name, name, l.Project.Name, l.Environment, last,
					orDash(strings.Join(names, ", ")), orDash(strings.Join(l.Waiting, ", ")))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(io.Out, "\nServices that wait are added in Settings, Managed services.")
			return nil
		},
	}
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}
