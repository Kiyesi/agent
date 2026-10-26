package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/guard"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/report"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
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
	guardProbe = realProbe
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

func newGuard(io IO) *cobra.Command {
	var (
		sites      []string
		restore    bool
		noRestore  bool
		configPath string
	)
	cmd := &cobra.Command{
		Use:   "guard -- <command>",
		Short: "The safe way to make a risky change: what works now, and each step to review and run",
		Long: "Kiyesi changes nothing and runs nothing. It reads how this server is now: the\n" +
			"grade, the failed services, the containers, and whether the server's own sites\n" +
			"answer. Then it prints the safe way to make your change, step by step, for you\n" +
			"to review and run: keep a copy of /etc and the package list, make the change,\n" +
			"check the same things again, and if something broke, see what changed, put back\n" +
			"the settings you choose and restart what failed.",
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
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi guard -- " + strings.Join(args, " ") + "\nReading the services and containers needs root."}
			}
			return guardOne(cmd.Context(), io, args, sites, noRestore, configPath)
		},
	}
	cmd.Flags().StringArrayVar(&sites, "check", nil, "an address on this server to check now and after, such as http://127.0.0.1:3000/health (repeat for more)")
	// --restore is kept so scripts written before 0.40.0 still run; Kiyesi
	// never puts settings back by itself now.
	cmd.Flags().BoolVar(&restore, "restore", false, "ignored: Kiyesi never changes anything")
	_ = cmd.Flags().MarkHidden("restore")
	cmd.Flags().BoolVar(&noRestore, "no-restore", false, "leave out the steps that put the settings back")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	cmd.AddCommand(newGuardList(io), newGuardUndo(io))
	return cmd
}

// guardOne is guard for one command: Kiyesi changes nothing and runs
// nothing. It reads how the server is now, then prints the safe way to make
// the change, step by step, for the person to review and run.
func guardOne(ctx context.Context, io IO, args, sites []string, noRestore bool, configPath string) error {
	out := render.NewWriter(io.Out, io.Environ)
	if len(sites) == 0 {
		sites = guard.DefaultSites(guardPorts())
	}
	now := guardProbe().Read(ctx, sites)
	if r, err := guardScan(ctx, configPath); err == nil {
		now.Letter, now.Score = r.Grade.Letter, r.Grade.Score
	}
	stamp := time.Now().Format("2006-01-02-1504")
	settings := "/root/etc-before-" + stamp + ".tgz"
	packages := "/root/packages-before-" + stamp + ".txt"
	list := "dpkg -l"
	if _, err := system.Find("dpkg"); err != nil {
		list = "rpm -qa"
	}
	var command []string
	for _, a := range args {
		command = append(command, shellWord(a))
	}
	check := []string{"systemctl --failed"}
	for _, site := range sites {
		check = append(check, "curl -s -o /dev/null -w '%{http_code}\\n' "+shellWord(site))
	}
	if len(now.Containers) > 0 {
		check = append(check, "sudo docker ps")
	}
	check = append(check, "sudo kiyesi scan")

	step := func(n int, text string, cmds ...string) {
		fmt.Fprintf(out, "  %d. %s\n", n, text)
		for _, c := range cmds {
			fmt.Fprintf(out, "       %s\n", c)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, render.Bold("Kiyesi changes nothing on this server.")+" "+neverRuns)
	fmt.Fprintf(out, "\nNow: %s\n\n", stateLine(now))
	fmt.Fprintln(out, "To make this change safely, review and run:")
	step(1, "If your provider offers snapshots, take one now.")
	step(2, "Keep a copy of the settings and the package list (in /root, so only root reads them):",
		"sudo tar -czf "+settings+" -C / etc",
		"sudo sh -c '"+list+" > "+packages+"'")
	step(3, "Make your change:", strings.Join(command, " "))
	step(4, "Check again, and compare with Now above:", check...)
	if !noRestore {
		step(5, "If something broke, see which settings changed, put back the ones you choose, and restart what failed:",
			"sudo tar -dzf "+settings+" -C /",
			"sudo tar -xzf "+settings+" -C / etc/<the file that changed>",
			"sudo systemctl restart <the service that failed>")
		step(6, "When all is well, delete the copy: it holds password hashes and keys.",
			"sudo rm "+settings+" "+packages)
	}
	fmt.Fprintln(out)
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

// putBack restores the settings and restarts what failed.
// printRestore shows the commands that put the changed settings back from
// guard's copy, and restart what failed, for the person to review and run.
func printRestore(out io.Writer, store guard.Store, m *guard.Manifest, changes []guard.Change, restart []string) {
	var cmds []string
	var left []string
	for _, c := range changes {
		dest := filepath.Join(m.Root, filepath.FromSlash(c.Path))
		switch {
		case c.Kind == "added":
			cmds = append(cmds, "sudo rm "+shellWord(dest))
		case c.Kept:
			cmds = append(cmds, "sudo cp -a "+shellWord(filepath.Join(store.Dir, m.ID, "files", filepath.FromSlash(c.Path)))+" "+shellWord(dest))
		default:
			left = append(left, dest)
		}
	}
	for _, u := range restart {
		cmds = append(cmds, "sudo systemctl restart "+shellWord(u))
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+render.Bold("Kiyesi changes nothing on this server.")+" "+neverRuns)
	if len(cmds) > 0 {
		fmt.Fprintln(out, "  To put the settings back as they were before "+strings.Join(m.Command, " ")+", review and run:")
		for _, c := range cmds {
			fmt.Fprintln(out, "    "+c)
		}
	} else {
		fmt.Fprintln(out, render.Grey("  No settings file it copied changed, so there is nothing to put back. The packages above are the likely cause."))
	}
	for _, l := range left {
		fmt.Fprintf(out, "  %s %s was not copied, so it stays as the command left it\n", render.Amber("!"), l)
	}
}

// shellWord quotes a word for a shell only when it needs it.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-@:+") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
			fmt.Fprintln(out, render.Grey("  How to put one run's settings back: sudo kiyesi guard undo <id>"))
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
		Short: "Show how to put /etc back as it was before one guarded run",
		Long: "Lists every settings file that changed since that run began, including\n" +
			"changes made after it, and the commands that put each back from guard's copy,\n" +
			"for you to review and run. Kiyesi changes nothing.",
		Example: "  sudo kiyesi guard undo 7f3a",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !guardAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi guard undo " + args[0]}
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
			printRestore(out, store, m, changes, nil)
			return nil
		},
	}
	// Kept so scripts written before 0.40.0 still run; they change nothing now.
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "ignored: Kiyesi never changes anything")
	_ = cmd.Flags().MarkHidden("yes")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	return cmd
}
