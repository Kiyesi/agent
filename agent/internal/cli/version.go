package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

func newVersion(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "version",
		Short:   "Print the version of this program",
		Example: "  kiyesi version --json",
		Args:    cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if asJSON {
				return render.JSON(io.Out, map[string]string{"version": version.Version, "commit": version.Commit})
			}
			// Piped, one plain line, as scripts read it; for a person, the mark and the company line.
			if !stdoutIsTerminal(io) {
				_, err := fmt.Fprintf(io.Out, "kiyesi %s\n", version.Full())
				return err
			}
			_, err := fmt.Fprintf(io.Out, "%s  kiyesi %s\n     %s\n", brandMark(io), version.Full(), copyright())
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}

// copyright is the company line, shown only in version and help: the product
// is always Kiyesi; the company's name is for legal lines (brand/README.md).
func copyright() string {
	return fmt.Sprintf("© %d Kiyesi Technologies · kiyesi.dev", time.Now().Year())
}

// stdoutIsTerminal says whether a person reads the output. Tests replace it.
var stdoutIsTerminal = func(io IO) bool { return isTerminal(io.Out) }

// brandMark is the accent over the amber dot, in colour unless NO_COLOR is set.
func brandMark(io IO) string {
	for _, e := range io.Environ {
		if strings.HasPrefix(e, "NO_COLOR=") {
			return " " + accent + dot
		}
	}
	return " " + accent + "\x1b[38;2;255;194;75m" + dot + "\x1b[39m"
}
