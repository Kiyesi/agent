package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// compareTitles name each part in words, and its rows' names.
var compareTitles = map[string]string{
	"system": "System", "security": "Security", "ports": "Open ports", "services": "Running services",
	"packages": "Packages", "containers": "Containers", "jobs": "Timed jobs", "checks": "Failing checks",
}

var compareNames = map[string]string{
	"system": "system", "kernel": "kernel", "timezone": "time zone", "grade": "grade",
	"ssh_password": "SSH password login", "ssh_root": "SSH root login", "ssh_ports": "SSH ports",
	"firewall": "firewall", "auto_updates": "automatic security updates",
}

func newCompare(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "compare <server> <server>",
		Short: "Set two servers that should be alike side by side, and list what differs",
		Long: "Compares two servers you can see, from what their agents last sent: the system\n" +
			"and kernel, SSH and firewall settings, open ports, running services, packages and\n" +
			"their versions, containers and their images, timed jobs and failing checks. Only\n" +
			"what differs is listed, with a count of what is the same.",
		Example: "  kiyesi compare web-1 web-2\n  kiyesi compare web-1 web-2 --json",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Servers(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			var ids []string
			for _, name := range args {
				s, ok := find(list, name)
				if !ok {
					return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", name)
				}
				ids = append(ids, s.ID)
			}
			if ids[0] == ids[1] {
				return usageErr("Choose two different servers. Example: kiyesi compare web-1 web-2")
			}
			r, err := c.Compare(cmd.Context(), ids[0], ids[1])
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, r)
			}
			printComparison(io, r)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the comparison as JSON")
	return cmd
}

func printComparison(io IO, r api.Comparison) {
	out := render.NewWriter(io.Out, io.Environ)
	fmt.Fprintln(out)
	for _, s := range []api.CompareSide{r.A, r.B} {
		if !s.Read {
			why := "its agent has not sent what is installed yet (Kiyesi 0.39.0 or later, within a day)"
			if !s.Covered {
				why = "the free plan does not watch it; add credit to compare it"
			}
			fmt.Fprintln(out, render.Amber("! ")+s.Name+": "+why)
		}
	}
	if !r.A.Read || !r.B.Read {
		if r.A.Read || r.B.Read {
			read := r.A.Name
			if r.B.Read {
				read = r.B.Name
			}
			fmt.Fprintf(out, "Only %s has been read so far, so this lists what it has, not differences.\n", read)
		} else {
			fmt.Fprintln(out, "Neither server has been read yet, so there is nothing to compare.")
			fmt.Fprintln(out)
			return
		}
	} else if r.Differences == 0 {
		fmt.Fprintf(out, "%s %s and %s are alike in everything Kiyesi compares.\n\n", render.Green("✓"), r.A.Name, r.B.Name)
		return
	} else {
		fmt.Fprintf(out, "%s and %s differ in %s.\n", render.Bold(r.A.Name), render.Bold(r.B.Name), plural(r.Differences, "thing", "things"))
	}
	for _, s := range r.Sections {
		if len(s.Rows) == 0 {
			continue
		}
		title := compareTitles[s.Key]
		if title == "" {
			title = s.Key
		}
		fmt.Fprintf(out, "\n%s %s\n", render.Bold(strings.ToUpper(title)), render.Grey(fmt.Sprintf("(%d the same)", s.Same)))
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		fmt.Fprintf(w, "  \t%s\t%s\n", r.A.Name, r.B.Name)
		for _, row := range s.Rows {
			name := row.Name
			if n, ok := compareNames[name]; ok {
				name = n
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\n", name, valueOr(row.A), valueOr(row.B))
		}
		_ = w.Flush()
		if s.More > 0 {
			fmt.Fprintln(out, render.Grey(fmt.Sprintf("  … and %d more that differ", s.More)))
		}
	}
	fmt.Fprintln(out)
}

func valueOr(v *string) string {
	if v == nil {
		return "—"
	}
	return *v
}
