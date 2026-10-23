package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/guard"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/report"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/send"
	"github.com/kiyesi/kiyesi/agent/internal/software"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// The server as kiyesi guard sees it. Tests replace each part.
var (
	guardAsRoot = func() bool { return os.Geteuid() == 0 }
	guardStore  = func() guard.Store { return guard.Store{Dir: guard.DefaultDir} }
	guardRoot   = "/etc"
	guardScan   = func(ctx context.Context, configPath string) (scan.Report, error) {
		r, _, err := runScan(ctx, configPath, slowChecksEvery, render.ByGuard)
		return r, err
	}
	guardProbe    = realProbe
	guardPackages = func(ctx context.Context) []string {
		sys := newSystem(true, report.Dir(true))
		var out []string
		for _, p := range software.Read(ctx, sys).Packages {
			out = append(out, p.Name+" "+p.Version)
		}
		return out
	}
	guardPorts = func() []int {
		sys := newSystem(true, report.Dir(true))
		ls, err := checks.NewEnv(sys, config.Default()).Listeners()
		if err != nil {
			return nil
		}
		var out []int
		for _, l := range ls {
			out = append(out, l.Port)
		}
		return out
	}
	guardRun     = runGuarded
	guardRestart = func(ctx context.Context, unit string) error {
		_, err := fix.RealHost{}.Run(ctx, "systemctl", "restart", unit)
		return err
	}
)

func realProbe() guard.Probe {
	return guard.Probe{
		Failed: func(ctx context.Context) []string {
			out, err := system.ExecRunner{}.Run(ctx, "systemctl", "--failed", "--plain", "--no-legend", "--no-pager")
			if err != nil && len(out) == 0 {
				return nil
			}
			return guard.ParseFailed(string(out))
		},
		Containers: func(ctx context.Context) []string {
			d := system.NewDocker(system.DockerSocket)
			if d == nil {
				return nil
			}
			cs, err := d.Containers(ctx)
			if err != nil {
				return nil
			}
			var names []string
			for _, c := range cs {
				if c.Status == "running" {
					names = append(names, c.Name)
				}
			}
			return names
		},
		Get: guard.SiteGetter(),
	}
}

// runGuarded runs the command with the terminal handed to it, as typed. A
// Ctrl-C reaches the command; guard waits for it, then checks again.
func runGuarded(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) (int, error) {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return 127, fmt.Errorf("%s is not a program on this server: %w", args[0], err)
	}
	cmd := exec.Command(path, args[1:]...) // #nosec G204 -- the command the person typed after --, run as they asked
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
	signal.Ignore(os.Interrupt, syscall.SIGQUIT)
	defer signal.Reset(os.Interrupt, syscall.SIGQUIT)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func newGuard(io IO) *cobra.Command {
	var (
		sites      []string
		restore    bool
		noRestore  bool
		configPath string
	)
	cmd := &cobra.Command{
		Use:   "guard -- <command>",
		Short: "A seatbelt for a risky change: save the settings, run a command, check again, offer to put them back",
		Long: "Before the command runs, saves a copy of /etc and notes what works: the grade,\n" +
			"the services, the containers, and the server's own sites. After, it checks again\n" +
			"and says what changed. If a service failed, a site stopped answering, a container\n" +
			"stopped or the grade fell, it offers to put the settings back and restart what\n" +
			"failed. Package upgrades are listed with the command to go back, never undone by\n" +
			"themselves. Password hashes and private keys are never copied. The copy stays on\n" +
			"this server, for root only; the last 5 are kept.",
		Example: "  sudo kiyesi guard -- apt-get upgrade\n" +
			"  sudo kiyesi guard --check http://127.0.0.1:3000/health -- ./deploy.sh\n" +
			"  sudo kiyesi guard list\n" +
			"  sudo kiyesi guard undo 7f3a",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || cmd.ArgsLenAtDash() != 0 {
				return usageErr("Put the command after --. Example: sudo kiyesi guard -- apt-get upgrade")
			}
			if restore && noRestore {
				return usageErr("Choose --restore or --no-restore, not both")
			}
			for _, s := range sites {
				if err := guard.LocalSite(s); err != nil {
					return usageErr("%v", err)
				}
			}
			if !guardAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi guard -- " + strings.Join(args, " ") + "\nSaving /etc and checking the services needs root."}
			}
			return guardOne(cmd.Context(), io, args, sites, restore, noRestore, configPath)
		},
	}
	cmd.Flags().StringArrayVar(&sites, "check", nil, "an address on this server to ask before and after, such as http://127.0.0.1:3000/health (repeat for more)")
	cmd.Flags().BoolVar(&restore, "restore", false, "put the settings back without asking when something broke")
	cmd.Flags().BoolVar(&noRestore, "no-restore", false, "never put the settings back; only say what broke")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	cmd.AddCommand(newGuardList(io), newGuardUndo(io))
	return cmd
}

func guardOne(ctx context.Context, io IO, args, sites []string, restore, noRestore bool, configPath string) error {
	out := render.NewWriter(io.Out, io.Environ)
	user := sudoUser(io.Environ)
	store := guardStore()
	fmt.Fprintln(out)
	fmt.Fprintln(out, render.Grey("Kiyesi guard · saving this server's settings first"))
	m, err := store.Snapshot(guardRoot, args, user, time.Now())
	if err != nil {
		return &exitError{code: ExitFindings, msg: "Nothing ran: the settings could not be saved: " + err.Error()}
	}
	kept, notKept := 0, 0
	for _, f := range m.Files {
		if f.Kept {
			kept++
		} else {
			notKept++
		}
	}
	saved := fmt.Sprintf("Saved %s (%d files", guardRoot, kept)
	if notKept > 0 {
		saved += fmt.Sprintf("; %d secret or big files noted, not copied", notKept)
	}
	fmt.Fprintf(out, "  %s %s) and the package list  %s\n", render.Green("✓"), saved, render.Grey("(guard "+m.ID+")"))
	if len(sites) == 0 {
		sites = guard.DefaultSites(guardPorts())
	}
	probe := guardProbe()
	m.Packages = guardPackages(ctx)
	m.Before = probe.Read(ctx, sites)
	if r, err := guardScan(ctx, configPath); err == nil {
		m.Before.Letter, m.Before.Score = r.Grade.Letter, r.Grade.Score
	}
	_ = store.Save(m)
	fmt.Fprintf(out, "  %s\n\n", stateLine(m.Before))
	fmt.Fprintln(out, render.Grey("── "+strings.Join(args, " ")+" "+strings.Repeat("─", max(0, 50-len(strings.Join(args, " "))))))
	start := time.Now()
	code, runErr := guardRun(ctx, args, io.In, io.Out, io.Err)
	took := time.Since(start).Round(time.Second)
	fmt.Fprintln(out, render.Grey(fmt.Sprintf("── done: exit %d, %s ──", code, took)))
	m.Exit = &code
	fmt.Fprintln(out, "\n"+render.Grey("  Checking again…"))
	after := probe.Read(ctx, sites)
	if r, err := guardScan(ctx, configPath); err == nil {
		after.Letter, after.Score = r.Grade.Letter, r.Grade.Score
	}
	m.After = &after
	_ = store.Save(m)
	changes := guard.Changes(m)
	pkgs := guard.PackageChanges(m.Packages, guardPackages(ctx))
	worse := guard.Worse(m.Before, after)

	if m.Before.Letter != "" && after.Letter != "" {
		fmt.Fprintf(out, "  %s %s %d  →  %s %s\n", render.Bold("GRADE"), render.GradeBlock(m.Before.Letter), m.Before.Score,
			render.GradeBlock(after.Letter), render.Bold(fmt.Sprintf("%d/100", after.Score)))
	}
	if len(worse) == 0 {
		fmt.Fprintf(out, "  %s %s\n", render.Green("✓"), "No service failed, the sites answer as before, and the containers still run")
	}
	for _, w := range worse {
		fmt.Fprintf(out, "  %s %s\n", render.Red("✗"), w)
	}
	printChanges(out, changes, pkgs)

	restoredNow, stillBroken := false, false
	if len(worse) > 0 && !noRestore && changesOff(configPath) {
		fmt.Fprintln(out, render.Grey("  Kiyesi does not change this server (fix: off), so it does not put the settings back. Its copy is in "+guard.DefaultDir+"/"+m.ID+"/files."))
	} else if len(worse) > 0 && !noRestore {
		backable := 0
		for _, c := range changes {
			if c.Kept {
				backable++
			}
		}
		failedNow := newlyFailed(m.Before.Failed, after.Failed)
		if backable > 0 {
			q := fmt.Sprintf("\nPut the %d settings %s back as they were", backable, plural(backable, "file", "files"))
			if len(failedNow) > 0 {
				q += ", and restart " + strings.Join(failedNow, ", ")
			}
			yes := restore
			if !yes {
				a := strings.ToLower(strings.TrimSpace(ask(io, q+"? [y/N] ")))
				yes = a == "y" || a == "yes"
			}
			if yes {
				restoredNow = putBack(ctx, out, store, m, changes, failedNow)
				if restoredNow {
					again := probe.Read(ctx, sites)
					if r, err := guardScan(ctx, configPath); err == nil {
						again.Letter, again.Score = r.Grade.Letter, r.Grade.Score
					}
					if still := guard.Worse(m.Before, again); len(still) == 0 {
						fmt.Fprintf(out, "  %s %s\n", render.Green("✓"), "Working again: "+stateLine(again))
					} else {
						stillBroken = true
						for _, w := range still {
							fmt.Fprintf(out, "  %s still: %s\n", render.Amber("!"), w)
						}
						fmt.Fprintln(out, render.Grey("  The settings are back; a service the command stopped may need starting again, such as: sudo systemctl restart nginx"))
					}
				}
			}
		} else {
			fmt.Fprintln(out, render.Grey("  No settings file changed, so there is nothing to put back. The packages above are the likely cause."))
		}
	}
	if !restoredNow {
		fmt.Fprintln(out, render.Grey("  To put the settings back later: sudo kiyesi guard undo "+m.ID))
	}
	fmt.Fprintln(out)
	tellService(m, changes, pkgs, worse, restoredNow)
	store.Prune()
	switch {
	case runErr != nil:
		return &exitError{code: ExitFindings, msg: runErr.Error()}
	case code != 0:
		return &exitError{code: min(max(code, 1), 125)}
	case len(worse) > 0 && (!restoredNow || stillBroken):
		return &exitError{code: ExitFindings}
	}
	return nil
}

func stateLine(st guard.State) string {
	parts := []string{}
	if st.Letter != "" {
		parts = append(parts, fmt.Sprintf("grade %s %d", st.Letter, st.Score))
	}
	parts = append(parts, plural(len(st.Failed), "failed service", "failed services"))
	answering := 0
	for _, code := range st.Sites {
		if code > 0 && code < 500 {
			answering++
		}
	}
	if len(st.Sites) > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d %s answer", answering, len(st.Sites), plural0(len(st.Sites), "site", "sites")))
	}
	parts = append(parts, plural(len(st.Containers), "container", "containers")+" running")
	return strings.Join(parts, " · ")
}

func plural0(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func printChanges(out io.Writer, changes []guard.Change, pkgs []guard.PackageChange) {
	if len(changes) == 0 && len(pkgs) == 0 {
		fmt.Fprintln(out, render.Grey("  Nothing in "+guardRoot+" and no package changed."))
		return
	}
	if len(changes) > 0 {
		fmt.Fprintf(out, "\n  %s\n", render.Bold(fmt.Sprintf("Settings changed: %d", len(changes))))
		for i, c := range changes {
			if i == 12 {
				fmt.Fprintln(out, render.Grey(fmt.Sprintf("    and %d more: sudo kiyesi guard list --json", len(changes)-12)))
				break
			}
			note := ""
			if !c.Kept {
				note = render.Grey("  (a secret or big file: not copied, so not put back)")
			}
			fmt.Fprintf(out, "    %-8s %s/%s%s\n", c.Kind, guardRoot, c.Path, note)
		}
	}
	if len(pkgs) > 0 {
		fmt.Fprintf(out, "\n  %s\n", render.Bold(fmt.Sprintf("Packages changed: %d", len(pkgs))))
		for i, p := range pkgs {
			if i == 12 {
				fmt.Fprintln(out, render.Grey(fmt.Sprintf("    and %d more", len(pkgs)-12)))
				break
			}
			what := p.Before + " → " + p.After
			switch {
			case p.Before == "":
				what = "installed " + p.After
			case p.After == "":
				what = "removed " + p.Before
			}
			fmt.Fprintf(out, "    %-28s %s\n", p.Name, what)
		}
		fmt.Fprintln(out, render.Grey("  Packages are never put back by themselves. To go back to one, if apt still has the old version:"))
		fmt.Fprintln(out, "    "+guard.BackCommand(pkgs[0]))
	}
}

func newlyFailed(before, after []string) []string {
	was := map[string]bool{}
	for _, u := range before {
		was[u] = true
	}
	var out []string
	for _, u := range after {
		if !was[u] {
			out = append(out, u)
		}
	}
	return out
}

// putBack restores the settings and restarts what failed.
func putBack(ctx context.Context, out io.Writer, store guard.Store, m *guard.Manifest, changes []guard.Change, restart []string) bool {
	restored, left, err := store.Restore(m, changes)
	if restored > 0 {
		now := time.Now().UTC()
		m.RestoredAt = &now
		_ = store.Save(m)
		fmt.Fprintf(out, "  %s Put back %s\n", render.Green("✓"), plural(restored, "settings file", "settings files"))
	}
	for _, l := range left {
		fmt.Fprintf(out, "  %s %s/%s was not copied, so it is as the command left it\n", render.Amber("!"), guardRoot, l)
	}
	if err != nil {
		fmt.Fprintf(out, "  %s %v\n", render.Red("✗"), err)
	}
	for _, u := range restart {
		if e := guardRestart(ctx, u); e != nil {
			fmt.Fprintf(out, "  %s %s did not restart: %v\n", render.Red("✗"), u, e)
		} else {
			fmt.Fprintf(out, "  %s Restarted %s\n", render.Green("✓"), u)
		}
	}
	return restored > 0
}

// tellService leaves a line for the server's History on a connected
// server: the program's name only, as a command line can hold a password.
func tellService(m *guard.Manifest, changes []guard.Change, pkgs []guard.PackageChange, worse []string, restored bool) {
	if _, _, err := loadConnection(); err != nil {
		return
	}
	prog := filepath.Base(m.Command[0])
	done := fmt.Sprintf("Guarded %s (exit %d): %s, %s", safeWord(prog), *m.Exit,
		plural(len(changes), "settings file", "settings files")+" changed", plural(len(pkgs), "package", "packages")+" changed")
	switch {
	case restored:
		done += "; something broke, and the settings were put back"
	case len(worse) > 0:
		done += "; " + worse[0]
	}
	now := time.Now()
	b := send.Items(now, send.Item{Kind: "fixed", At: now.UTC().Format(time.RFC3339),
		Fixed: &send.Fixed{ID: m.ID, Fix: "guard", Done: truncate(done, 280), User: m.User}})
	ob := send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes}
	_ = ob.Put(b, now)
}

// safeWord keeps a program's name to letters, digits and . _ -.
func safeWord(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 40 {
			break
		}
		if r == '.' || r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "a command"
	}
	return b.String()
}

func newGuardList(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the last guarded runs on this server",
		Example: "  sudo kiyesi guard list",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !guardAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi guard list"}
			}
			list, err := guardStore().List()
			if err != nil {
				return err
			}
			if asJSON {
				return jsonOut(io.Out, list)
			}
			if len(list) == 0 {
				fmt.Fprintln(io.Out, "No guarded runs on this server yet. Try: sudo kiyesi guard -- apt-get upgrade")
				return nil
			}
			out := render.NewWriter(io.Out, io.Environ)
			for _, m := range list {
				exit := "did not finish"
				if m.Exit != nil {
					exit = fmt.Sprintf("exit %d", *m.Exit)
				}
				state := ""
				if m.After != nil {
					if w := guard.Worse(m.Before, *m.After); len(w) > 0 {
						state = render.Red(" · " + w[0])
					}
				}
				if m.RestoredAt != nil {
					state += render.Grey(" · settings put back")
				}
				fmt.Fprintf(out, "  %s  %s  %s by %s · %s%s\n", render.Bold(m.ID), m.At.Local().Format("2 Jan 15:04"), strings.Join(m.Command, " "), m.User, exit, state)
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, render.Grey("  Put one run's settings back: sudo kiyesi guard undo <id>"))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the runs as JSON")
	return cmd
}

func newGuardUndo(io IO) *cobra.Command {
	var yes bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "undo <id>",
		Short: "Put /etc back as it was before one guarded run, after a yes",
		Long: "Puts back every settings file that changed since that run began: changed and\n" +
			"removed files from its copy, and files added since taken away. That includes\n" +
			"changes made after it, so it lists them first and asks.",
		Example: "  sudo kiyesi guard undo 7f3a",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !guardAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi guard undo " + args[0]}
			}
			if changesOff(configPath) {
				return &exitError{code: ExitNoAccess, msg: "Kiyesi does not change this server (fix: off in " + configPath + "). Its copy of the settings is in " + guard.DefaultDir + "/" + args[0] + "/files."}
			}
			store := guardStore()
			m, err := store.Get(args[0])
			if err != nil {
				return &exitError{code: ExitUsage, msg: err.Error()}
			}
			out := render.NewWriter(io.Out, io.Environ)
			changes := guard.Changes(m)
			if len(changes) == 0 {
				fmt.Fprintln(out, "Nothing in "+m.Root+" differs from before that run.")
				return nil
			}
			printChanges(out, changes, nil)
			if !yes {
				a := strings.ToLower(strings.TrimSpace(ask(io, "\nPut these back as they were before "+strings.Join(m.Command, " ")+"? [y/N] ")))
				if a != "y" && a != "yes" {
					fmt.Fprintln(out, "Nothing changed.")
					return nil
				}
			}
			if !putBack(cmd.Context(), out, store, m, changes, nil) {
				return &exitError{code: ExitFindings}
			}
			fmt.Fprintln(out, render.Grey("  Restart the services whose settings changed, such as: sudo systemctl restart nginx"))
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "put them back without asking")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	return cmd
}
