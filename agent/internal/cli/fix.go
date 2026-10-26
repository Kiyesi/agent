package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// neverRuns is Kiyesi's promise, said wherever a command could have
// changed the server: it only suggests, and a person runs each command.
const neverRuns = "It only suggests: you review each command and run it yourself."

// Where earlier versions of kiyesi fix kept what they changed, for kiyesi
// fix undo; tests replace them.
var (
	fixStoreDir = fix.DefaultDir
	fixAsRoot   = func() bool { return os.Geteuid() == 0 }
	fixTerminal = func(io IO) bool { f, ok := io.In.(*os.File); return ok && isTerminal(f) }
)

func newFix(io IO) *cobra.Command {
	var dryRun, yes, asJSON bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "fix [name...]",
		Short: "List what to fix on this server, with the commands to review and run (needs sudo)",
		Long: "Scans this server, then lists each problem with the commands that fix it, worst\n" +
			"first, for you to review and run yourself. Kiyesi never changes the server: not\n" +
			"this command, not the agent, not the dashboard. Names narrow the list to what\n" +
			"those fixes cover: " + strings.Join(fix.Names(), ", ") + ".\n\n" +
			"Changes made by kiyesi fix before 0.40.0 can still be listed and put back:\n" +
			"sudo kiyesi fix undo.",
		Example: "  sudo kiyesi fix                 every problem, with its commands\n" +
			"  sudo kiyesi fix ssh-password    only what that fix covers\n" +
			"  sudo kiyesi fix --json          the same, as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, a := range args {
				if fix.ByName(a) == nil {
					return usageErr("There is no fix called %q. The fixes are: %s.", a, strings.Join(fix.Names(), ", "))
				}
			}
			if !fixAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo, so the scan can read every setting: sudo kiyesi fix"}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return suggest(ctx, io, configPath, args, asJSON)
		},
	}
	// Kept so scripts written for kiyesi fix before 0.40.0 still run; they
	// change nothing now.
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "ignored: kiyesi fix never changes anything")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "ignored: kiyesi fix never changes anything")
	_ = cmd.Flags().MarkHidden("dry-run")
	_ = cmd.Flags().MarkHidden("yes")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the list as JSON")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	cmd.AddCommand(newFixUndo(io))
	return cmd
}

func newFixUndo(io IO) *cobra.Command {
	var yes, asJSON bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "undo [id]",
		Short: "List what kiyesi fix changed before 0.40.0, and the commands that put one back (needs sudo)",
		Long: "Before 0.40.0, kiyesi fix could make a change after a yes, and kept a record of\n" +
			"each. Alone, this lists those changes, newest first, with their ids. With an id,\n" +
			"it prints the commands that put that change back as it was, for you to review\n" +
			"and run. Kiyesi changes nothing.",
		Example: "  sudo kiyesi fix undo\n  sudo kiyesi fix undo 7f3a",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !fixAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo, as only root reads the records: sudo kiyesi fix undo"}
			}
			store := &fix.Store{Dir: fixStoreDir}
			out := render.NewWriter(io.Out, io.Environ)
			if len(args) == 0 {
				return listFixes(io, out, store, asJSON)
			}
			rec, err := store.Get(args[0])
			if err != nil {
				return usageErr("%v", err)
			}
			if !rec.CanUndo {
				return &exitError{code: ExitUsage, msg: fmt.Sprintf("%s (%s) cannot be put back: it installed updates, renewed certificates or removed unused Docker images.", rec.ID, rec.Done)}
			}
			cmds, notes := fix.UndoCommands(rec)
			if asJSON {
				return render.JSON(io.Out, map[string]any{"changed": false, "id": rec.ID, "done": rec.Done, "commands": cmds, "notes": notes})
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, render.Bold("Kiyesi changes nothing on this server.")+" "+neverRuns)
			fmt.Fprintf(out, "\nTo put back %q, made by %s on %s, review and run:\n", rec.Done, rec.User, rec.At.Local().Format("2 Jan 15:04"))
			for _, n := range notes {
				fmt.Fprintf(out, "  %s %s\n", render.Amber("First:"), n)
			}
			for _, c := range cmds {
				for k, line := range strings.Split(c, "\n") {
					if k == 0 {
						fmt.Fprintf(out, "  %s\n", line)
					} else {
						fmt.Fprintf(out, "    %s\n", line)
					}
				}
			}
			fmt.Fprintln(out)
			return nil
		},
	}
	// Kept so scripts written before 0.40.0 still run; they change nothing now.
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "ignored: Kiyesi never changes anything")
	_ = cmd.Flags().MarkHidden("yes")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the list, or the commands, as JSON")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	return cmd
}

func listFixes(io IO, out io.Writer, store *fix.Store, asJSON bool) error {
	recs, err := store.List()
	if err != nil {
		return &exitError{code: ExitNoAccess, msg: "Cannot read " + store.Dir + ": " + err.Error()}
	}
	if asJSON {
		return jsonOut(io.Out, recs)
	}
	if len(recs) == 0 {
		fmt.Fprintln(out, "kiyesi fix has not changed anything on this server.")
		return nil
	}
	fmt.Fprintln(out)
	for _, r := range recs {
		state := "how to put it back: sudo kiyesi fix undo " + r.ID
		switch {
		case r.UndoneAt != nil:
			state = "undone " + r.UndoneAt.Local().Format("2 Jan 15:04")
		case !r.CanUndo:
			state = "cannot be undone"
		}
		fmt.Fprintf(out, "  %s  %s  %s  %s\n", render.Bold(r.ID), r.At.Local().Format("2 Jan 15:04"), r.Done, render.Grey("("+r.User+" · "+state+")"))
	}
	fmt.Fprintln(out)
	return nil
}

// suggestion is one finding's commands, for a person to review and run.
type suggestion struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Sentence string `json:"sentence"`
	// Why says why it matters and what to check before running the
	// commands, such as that your key works before passwords go off.
	Why      string `json:"why"`
	Commands string `json:"commands"`
}

// suggest is kiyesi fix: it scans, then shows each finding's commands for
// the person to review and run themselves, and changes nothing. names
// narrow it to the checks those fixes cover.
func suggest(ctx context.Context, io IO, configPath string, names []string, asJSON bool) error {
	r, _, err := runScan(ctx, configPath, 0, render.ByScan)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, n := range names {
		for _, t := range fix.ByName(n).Targets() {
			want[t.Check] = true
		}
	}
	var list []suggestion
	for _, sev := range []string{"critical", "warning"} {
		for _, c := range r.Checks {
			for _, f := range c.Findings {
				if f.Severity != sev || strings.TrimSpace(f.Fix) == "" || (len(want) > 0 && !want[c.ID]) {
					continue
				}
				list = append(list, suggestion{Check: c.ID, Severity: f.Severity, Sentence: f.Sentence, Why: strings.TrimSpace(f.Why), Commands: f.Fix})
			}
		}
	}
	if asJSON {
		if list == nil {
			list = []suggestion{}
		}
		return render.JSON(io.Out, map[string]any{"changed": false, "suggestions": list})
	}
	out := render.NewWriter(io.Out, io.Environ)
	fmt.Fprintln(out)
	fmt.Fprintln(out, render.Bold("Kiyesi changes nothing on this server.")+" "+neverRuns)
	if len(list) == 0 {
		fmt.Fprintln(out, "\nNothing to fix: no finding has a command to run.")
		return nil
	}
	fmt.Fprintln(out, "\nWhat to do, for you to review and run yourself:")
	for _, s := range list {
		label := render.Amber(" WARN ")
		if s.Severity == "critical" {
			label = render.Red(" FAIL ")
		}
		fmt.Fprintf(out, "\n%s %s\n", label, s.Sentence)
		if s.Why != "" {
			fmt.Fprintf(out, "       Why: %s\n", s.Why)
		}
		for _, line := range strings.Split(s.Commands, "\n") {
			fmt.Fprintf(out, "       %s\n", line)
		}
	}
	fmt.Fprintln(out, "\n"+render.Bold("Read each command before you run it.")+" It changes your server, and you are the one who runs it.")
	return nil
}
