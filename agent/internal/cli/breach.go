package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/collect"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/keys"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/report"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// breachAsRoot says whether the check runs as root. Tests replace it.
var breachAsRoot = func() bool { return os.Geteuid() == 0 }

func newBreachCheck(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "breach-check",
		Short: "Look for signs that someone already got into this server. Nothing leaves the server",
		Long: "Answers one question: has someone already got in? It compares the system's\n" +
			"programs with the packages they came from, and looks for crypto miners,\n" +
			"programs run from temporary folders, autostart entries that download and run\n" +
			"code, a second root account, a library loaded into every program, and history\n" +
			"or sign-in logs turned off. Each sign says what it means and what to do.\n" +
			"Two notes cost no points and ask you to confirm a change was your team's: a\n" +
			"login account added since the last scan, and login keys changed in the last 7\n" +
			"days. For changed keys it shows the SSH sign-ins within a day of the change,\n" +
			"with the key each used, to compare with sudo kiyesi keys and your own key.\n" +
			"Comparing every program with its package can take a minute on a small server.\n" +
			"It only reads, needs root, and sends nothing. The same check runs in every scan.",
		Example: "  sudo kiyesi breach-check\n  sudo kiyesi breach-check --json   # exit 1 when there is a sign of a break-in",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !breachAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi breach-check\n" +
					"Other users' schedules, login keys and programs can be read only by root, and\n" +
					"\"no signs\" without them would mislead."}
			}
			pack, err := packs.English()
			if err != nil {
				return &exitError{code: ExitUsage, msg: "The built-in wording is damaged: " + err.Error() + ". Reinstall Kiyesi."}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			sys := newSystem(true, report.Dir(true))
			env := checks.NewEnv(sys, config.Default())
			out := render.NewWriter(io.Out, io.Environ)
			if !asJSON {
				fmt.Fprintln(out)
				fmt.Fprintln(out, render.Grey("  Comparing every system program with the package it came from. Each one is"))
				fmt.Fprintln(out, render.Grey("  read through, so on a small server this can take a minute…"))
			}
			r := scan.Run(ctx, env, checks.BreakIn(), pack)
			life := scan.Run(ctx, env, checks.EndOfLife(), pack)
			if asJSON {
				if err := render.JSON(io.Out, r.Checks); err != nil {
					return err
				}
			} else if err := render.BreakIn(out, r, render.BreakInDetail{
				Signs: len(pack.Check("break-in").Findings),
				Below: keyChangeSignins(ctx, sys, r),
				Life:  life.Checks,
			}); err != nil {
				return err
			}
			return failure(r, "critical")
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

// keyChangeSignins are the lines under each "login keys changed" note: the
// SSH sign-ins within a day either side of the change, with the key each
// used where SSH logged it, named from the keys on this server. They are
// read here and printed here; nothing is sent.
func keyChangeSignins(ctx context.Context, sys *system.System, r scan.Report) map[int][]string {
	raw, ok := r.Raw("break-in")
	if !ok {
		return nil
	}
	all := keys.Read(sys.FS)
	names := map[string]string{}
	for _, k := range all {
		if k.Comment != "" {
			names[k.Fingerprint] = k.Comment
		}
	}
	out := map[int][]string{}
	for i, f := range raw.Findings {
		if f.Key != "new-key" {
			continue
		}
		var changed time.Time
		for _, k := range all {
			if k.User == f.Vars["user"] && k.ChangedAt.After(changed) {
				changed = k.ChangedAt
			}
		}
		if changed.IsZero() {
			continue
		}
		at := changed.UTC().Format("2 Jan 15:04 UTC")
		list := collect.SigninsBetween(ctx, sys, changed.Add(-24*time.Hour), changed.Add(24*time.Hour), 20)
		if len(list) == 0 {
			out[i] = []string{render.Grey("No SSH sign-ins within a day of the change (" + at + ") in the sign-in log.")}
			continue
		}
		lines := []string{render.Bold("SSH sign-ins within a day of the change (" + at + "):")}
		for _, s := range list {
			l := fmt.Sprintf("  %s  %s from %s", s.At.UTC().Format("2 Jan 15:04"), s.User, s.Address)
			if s.Key != "" {
				l += ", key " + s.Key[:15] + "…"
				if n := names[s.Key]; n != "" {
					l += " (" + n + ")"
				}
			} else {
				l += ", with " + s.Method
			}
			lines = append(lines, l)
		}
		out[i] = lines
	}
	return out
}
