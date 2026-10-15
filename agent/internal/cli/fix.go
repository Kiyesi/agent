package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/send"
)

// What kiyesi fix changes the server through, and where it keeps its
// records; tests replace them.
var (
	fixHost      fix.Host = fix.RealHost{}
	fixStoreDir           = fix.DefaultDir
	fixAsRoot             = func() bool { return os.Geteuid() == 0 }
	fixTerminal           = func(io IO) bool { f, ok := io.In.(*os.File); return ok && isTerminal(f) }
	fixSystemsOK          = []string{"debian", "ubuntu"}
)

func newFix(io IO) *cobra.Command {
	var dryRun, yes, asJSON bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "fix [name...]",
		Short: "Fix what Kiyesi can fix on this server, after you say yes (needs sudo)",
		Long: "Lists the findings Kiyesi can fix for you, says in plain words what each fix\n" +
			"changes, and asks. After you say yes it makes the changes, checks the server\n" +
			"again and shows the new grade. Every change that can be undone is kept:\n" +
			"kiyesi fix undo lists them. Before a fix changes a file it saves it, and a fix\n" +
			"that fails halfway is put back at once.\n\n" +
			"Only you run this, at this server's terminal. The agent's service never runs\n" +
			"it, and the dashboard cannot ask for it. To forbid it on a server, set\n" +
			"fix: off in /etc/kiyesi/config.yaml. Names: " + strings.Join(fix.Names(), ", ") + ".",
		Example: "  sudo kiyesi fix                 the list, then asks\n" +
			"  sudo kiyesi fix ssh-password    one fix\n" +
			"  sudo kiyesi fix --dry-run       only show what it would change\n" +
			"  sudo kiyesi fix undo            what can be undone",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, a := range args {
				if fix.ByName(a) == nil {
					return usageErr("There is no fix called %q. The fixes are: %s.", a, strings.Join(fix.Names(), ", "))
				}
			}
			if asJSON && !dryRun && !yes {
				return usageErr("With --json, add --dry-run to only see the plan, or --yes to make the changes.")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runFix(ctx, io, configPath, args, dryRun, yes, asJSON)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "only show what each fix would change; change nothing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "make every change without asking, for a script you have read")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the plan, or what changed, as JSON (with --dry-run or --yes)")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	cmd.AddCommand(newFixUndo(io))
	return cmd
}

// fixReady checks the things every fix needs: root, the setting, the system.
func fixReady(configPath, what string) (config.Config, error) {
	if !fixAsRoot() {
		return config.Config{}, &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi " + what}
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return cfg, usageErr("%v\nFix the file, or move it away to use the defaults.", err)
	}
	if cfg.Fix == "off" {
		return cfg, &exitError{code: ExitNoAccess, msg: "kiyesi fix is turned off on this server (fix: off in " + configPath + "). Run the fix commands in the report yourself: sudo kiyesi scan"}
	}
	return cfg, nil
}

// planned is one fix with its findings and its plan.
type planned struct {
	fixer    fix.Fixer
	findings []scan.Finding
	in       fix.Input
	plan     fix.Plan
}

type fixJSON struct {
	Name     string   `json:"name"`
	Findings []string `json:"findings"`
	Plan     string   `json:"plan,omitempty"`
	Refused  string   `json:"refused,omitempty"`
	Skipped  string   `json:"skipped,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Undoable bool     `json:"undoable"`
	Result   string   `json:"result,omitempty"`
	UndoID   string   `json:"undo_id,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func runFix(ctx context.Context, io IO, configPath string, names []string, dryRun, yes, asJSON bool) error {
	cfg, err := fixReady(configPath, "fix")
	if err != nil {
		return err
	}
	before, env, _, err := scanWithEnv(ctx, configPath, 0)
	if err != nil {
		return err
	}
	if !slices.Contains(fixSystemsOK, env.Sys.OS.ID) {
		return &exitError{code: ExitUsage, msg: "kiyesi fix works on Debian and Ubuntu for now, and this is " + env.Sys.OS.Name + ". Run the fix commands in the report yourself: sudo kiyesi scan"}
	}
	list := planFixes(ctx, before, env, cfg, names, io.Environ)
	out := render.NewWriter(io.Out, io.Environ)

	if !asJSON {
		printPlan(out, before, list, names)
	}
	var todo []*planned
	for _, p := range list {
		if p.plan.Refuse == "" && p.plan.Skip == "" {
			todo = append(todo, p)
		}
	}
	if dryRun || len(todo) == 0 {
		if asJSON {
			return jsonOut(io.Out, fixesJSON(list, nil))
		}
		if dryRun && len(todo) > 0 {
			fmt.Fprintln(out, render.Grey("Nothing was changed. To make these changes: sudo kiyesi fix"))
		}
		return nil
	}
	if !yes {
		if !fixTerminal(io) {
			return usageErr("kiyesi fix asks before it changes anything. Run it in a terminal, or add --yes once you have read the plan (sudo kiyesi fix --dry-run).")
		}
		todo = choose(io, todo)
		if len(todo) == 0 {
			fmt.Fprintln(out, "Nothing was changed.")
			return nil
		}
	}

	store := &fix.Store{Dir: fixStoreDir}
	results := map[string]fixJSON{}
	var sent []send.Fixed
	failed := 0
	for _, p := range todo {
		// The one slow fix says so while it works.
		if !asJSON && p.fixer.Name() == "updates" {
			fmt.Fprintln(out, render.Grey("  … Installing updates. This can take a few minutes."))
		}
		rec, err := fix.Run(ctx, fixHost, store, p.fixer, p.in, p.plan)
		r := fixJSON{Name: p.fixer.Name()}
		if err != nil {
			failed++
			r.Error = err.Error()
			if !asJSON {
				fmt.Fprintf(out, "  %s %s: %s. %s\n", render.Red("✗"), p.fixer.Name(), strings.TrimSuffix(err.Error(), "."), render.Grey("Nothing was changed."))
			}
		} else {
			r.Result, r.UndoID = rec.Done, rec.ID
			sent = append(sent, send.Fixed{ID: rec.ID, Fix: rec.Fix, Done: rec.Done, User: rec.User})
			if !asJSON {
				undo := ""
				if rec.CanUndo {
					undo = render.Grey("  (undo: sudo kiyesi fix undo " + rec.ID + ")")
				}
				fmt.Fprintf(out, "  %s %s%s\n", render.Green("✓"), rec.Done, undo)
			}
		}
		results[p.fixer.Name()] = r
	}
	if len(sent) > 0 {
		rescanAndSend(ctx, out, configPath, before, sent, asJSON)
	}
	if asJSON {
		if err := jsonOut(io.Out, fixesJSON(list, results)); err != nil {
			return err
		}
	}
	if failed > 0 {
		return &exitError{code: ExitFindings}
	}
	return nil
}

// planFixes groups the findings by the fix that answers them and plans
// each, in the fixes' own order.
func planFixes(ctx context.Context, r scan.Report, env *checks.Env, cfg config.Config, names []string, environ []string) []*planned {
	byName := map[string]*planned{}
	for _, c := range r.Checks {
		raw, ok := r.Raw(c.ID)
		if !ok || raw.Status != checks.StatusFail {
			continue
		}
		// The report's findings are in the same order as the check's.
		for i, f := range raw.Findings {
			x := fix.For(c.ID, f)
			if x == nil || (len(names) > 0 && !slices.Contains(names, x.Name())) {
				continue
			}
			p := byName[x.Name()]
			if p == nil {
				p = &planned{fixer: x}
				byName[x.Name()] = p
			}
			p.in.Findings = append(p.in.Findings, f)
			if i < len(c.Findings) {
				p.findings = append(p.findings, c.Findings[i])
			}
		}
	}
	user := "root"
	for _, e := range environ {
		if v, ok := strings.CutPrefix(e, "SUDO_USER="); ok && v != "" {
			user = v
		}
	}
	var public []int
	if ls, err := env.Listeners(); err == nil {
		for _, l := range ls {
			public = append(public, l.Port)
		}
	}
	chosen := map[string]bool{}
	var out []*planned
	for _, x := range fix.All() {
		p := byName[x.Name()]
		if p == nil {
			continue
		}
		p.in.Cfg, p.in.User, p.in.Public, p.in.Planned = cfg, user, public, chosen
		p.plan = x.Plan(ctx, fixHost, p.in)
		if p.plan.Refuse == "" && p.plan.Skip == "" {
			chosen[x.Name()] = true
		}
		out = append(out, p)
	}
	return out
}

func printPlan(out io.Writer, r scan.Report, list []*planned, names []string) {
	fmt.Fprintln(out)
	head := fmt.Sprintf("%s %s %s", render.Bold("GRADE"), render.GradeBlock(r.Grade.Letter), render.Bold(fmt.Sprintf("%d/100", r.Grade.Score)))
	n := 0
	for _, p := range list {
		if p.plan.Refuse == "" && p.plan.Skip == "" {
			n++
		}
	}
	switch {
	case len(list) == 0 && len(names) > 0:
		fmt.Fprintf(out, "%s     Nothing to fix for %s: %s.\n\n", head, strings.Join(names, ", "), passedWord(len(names)))
		return
	case len(list) == 0:
		left := r.Counts.Critical + r.Counts.Warnings
		if left == 0 {
			fmt.Fprintf(out, "%s     Nothing to fix. Lovely. ✨\n\n", head)
		} else {
			fmt.Fprintf(out, "%s     Nothing here Kiyesi can fix by itself. %s need a person: sudo kiyesi scan\n\n", head, plural(left, "finding", "findings"))
		}
		return
	case n == 0:
		fmt.Fprintf(out, "%s     Kiyesi could fix these, but not safely right now:\n\n", head)
	default:
		fmt.Fprintf(out, "%s     Kiyesi can fix %s for you:\n\n", head, plural(n, "thing", "things"))
	}
	i := 0
	for _, p := range list {
		i++
		var titles []string
		for _, f := range p.findings {
			titles = append(titles, f.Sentence)
		}
		if len(titles) > 3 {
			titles = append(titles[:2], fmt.Sprintf("and %d more", len(titles)-2))
		}
		fmt.Fprintf(out, "  %d. %s %s\n", i, render.Bold(strings.Join(titles, "; ")), render.Grey("("+p.fixer.Name()+")"))
		switch {
		case p.plan.Skip != "":
			fmt.Fprintln(out, "     "+render.Grey(p.plan.Skip))
		case p.plan.Refuse != "":
			fmt.Fprintln(out, "     "+render.Amber("Left to you: ")+p.plan.Refuse)
		default:
			fmt.Fprintln(out, "     "+p.plan.Say)
			for _, w := range p.plan.Warn {
				fmt.Fprintln(out, "     "+render.Amber("! ")+w)
			}
		}
		fmt.Fprintln(out)
	}
}

func passedWord(n int) string {
	if n == 1 {
		return "it passed, or does not apply here"
	}
	return "they passed, or do not apply here"
}

// choose asks once for all, or one by one, and once more for a fix that
// warns of something serious, such as ports closing.
func choose(io IO, todo []*planned) []*planned {
	q := fmt.Sprintf("Fix all %d? [y/N/choose] ", len(todo))
	if len(todo) == 1 {
		q = "Make this change? [y/N] "
	}
	a := strings.ToLower(strings.TrimSpace(ask(io, q)))
	var picked []*planned
	switch {
	case a == "y" || a == "yes":
		picked = todo
	case (a == "c" || a == "choose") && len(todo) > 1:
		for _, p := range todo {
			if b := strings.ToLower(strings.TrimSpace(ask(io, "  "+p.fixer.Name()+"? [y/N] "))); b == "y" || b == "yes" {
				picked = append(picked, p)
			}
		}
	default:
		return nil
	}
	var out []*planned
	for _, p := range picked {
		if p.plan.Confirm {
			if b := strings.ToLower(strings.TrimSpace(ask(io, "  "+p.fixer.Name()+": "+p.plan.Warn[0]+"\n  Go on with this one? [y/N] "))); b != "y" && b != "yes" {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// rescanAndSend checks the server again, prints the grade's move, and,
// when the server is connected, leaves the scan and the changes for the
// agent's service to send: the dashboard shows them within a minute.
func rescanAndSend(ctx context.Context, out io.Writer, configPath string, before scan.Report, fixed []send.Fixed, quiet bool) {
	if !quiet {
		fmt.Fprintln(out, "\n"+render.Grey("  Checking again…"))
	}
	after, _, err := runScan(ctx, configPath, 0)
	if err != nil {
		if !quiet {
			fmt.Fprintln(out, render.Grey("  The server could not be checked again: "+err.Error()))
		}
		return
	}
	if !quiet {
		cheer := ""
		switch {
		case after.Grade.Score > before.Grade.Score && after.Grade.Letter == "A":
			cheer = "  🎉"
		case after.Grade.Score > before.Grade.Score:
			cheer = "  ✨"
		}
		fmt.Fprintf(out, "\n  %s %s %d  →  %s %s%s\n\n", render.Bold("GRADE"),
			render.GradeBlock(before.Grade.Letter), before.Grade.Score,
			render.GradeBlock(after.Grade.Letter), render.Bold(fmt.Sprintf("%d/100", after.Grade.Score)), cheer)
	}
	if _, _, err := loadConnection(); err == nil {
		ob := send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes}
		if err := ob.Put(send.Fixes(after, time.Now(), fixed), time.Now()); err == nil && !quiet {
			fmt.Fprintln(out, render.Grey("  The dashboard shows the new grade within a minute."))
		}
	}
}

func fixesJSON(list []*planned, results map[string]fixJSON) []fixJSON {
	var out []fixJSON
	for _, p := range list {
		j := fixJSON{Name: p.fixer.Name(), Plan: p.plan.Say, Refused: p.plan.Refuse, Skipped: p.plan.Skip, Warnings: p.plan.Warn, Undoable: p.plan.Undoable}
		for _, f := range p.findings {
			j.Findings = append(j.Findings, f.Sentence)
		}
		if r, ok := results[p.fixer.Name()]; ok {
			j.Result, j.UndoID, j.Error = r.Result, r.UndoID, r.Error
		}
		out = append(out, j)
	}
	return out
}

func newFixUndo(io IO) *cobra.Command {
	var yes, asJSON bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "undo [id]",
		Short: "List what kiyesi fix changed, or put one change back (needs sudo)",
		Long: "Alone, lists every change kiyesi fix made on this server, newest first, with\n" +
			"its id. With an id, puts that change back as it was: the files it changed are\n" +
			"restored and the service it touched is reloaded. Installing updates cannot\n" +
			"be undone.",
		Example: "  sudo kiyesi fix undo\n  sudo kiyesi fix undo 7f3a",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !fixAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi fix undo"}
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
			if !yes {
				if !fixTerminal(io) {
					return usageErr("kiyesi fix undo asks first. Run it in a terminal, or add --yes.")
				}
				if a := strings.ToLower(strings.TrimSpace(ask(io, fmt.Sprintf("Undo %q, made by %s on %s? [y/N] ", rec.Done, rec.User, rec.At.Local().Format("2 Jan 15:04"))))); a != "y" && a != "yes" {
					fmt.Fprintln(out, "Nothing was changed.")
					return nil
				}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := store.Undo(ctx, fixHost, rec); err != nil {
				return &exitError{code: ExitFindings, msg: "Not undone: " + err.Error()}
			}
			if asJSON {
				return render.JSON(io.Out, map[string]any{"undone": rec.ID, "fix": rec.Fix, "done": rec.Done})
			}
			fmt.Fprintf(out, "  %s Undone: %s\n", render.Green("✓"), rec.Done)
			user := "root"
			for _, e := range io.Environ {
				if v, ok := strings.CutPrefix(e, "SUDO_USER="); ok && v != "" {
					user = v
				}
			}
			before, _, err := runScan(ctx, configPath, 0)
			if err == nil {
				// The grade before the undo is not known here, so the scan is sent without a move.
				if _, _, cerr := loadConnection(); cerr == nil {
					ob := send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes}
					_ = ob.Put(send.Fixes(before, time.Now(), []send.Fixed{{ID: rec.ID, Fix: rec.Fix, Done: rec.Done, User: user, Undo: true}}), time.Now())
				}
				fmt.Fprintf(out, "  %s %s %s\n\n", render.Bold("GRADE"), render.GradeBlock(before.Grade.Letter), render.Bold(fmt.Sprintf("%d/100", before.Grade.Score)))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "undo without asking")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the list, or what was undone, as JSON")
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
		state := "undo: sudo kiyesi fix undo " + r.ID
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
