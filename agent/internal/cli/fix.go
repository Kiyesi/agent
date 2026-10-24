package cli

import (
	"context"
	"errors"
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
			"that fails halfway is put back at once. Three cannot be undone: installing\n" +
			"updates (updates), renewing certificates (certificates) and removing unused\n" +
			"Docker images and build cache (docker-cleanup).\n\n" +
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

// fixWorksHere is false where kiyesi fix refuses whatever is found: the
// setting turns it off, or the system is not one it knows.
func fixWorksHere(cfg config.Config, osID string) bool {
	return cfg.Fix != "off" && slices.Contains(fixSystemsOK, osID)
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

// changesOff says whether the server's settings forbid Kiyesi to change it
// (fix: off): kiyesi fix, kiyesi keys remove and kiyesi guard's putting
// back all keep to it.
func changesOff(configPath string) bool {
	cfg, err := config.Load(configPath)
	return err == nil && cfg.Fix == "off"
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
	before, env, _, err := scanWithEnv(ctx, configPath, 0, render.ByScan)
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
	var applied []*planned
	worked := map[string]bool{}
	failed := 0
	for _, p := range todo {
		// Not needed once the fix it waited on has worked.
		if p.plan.Unless != "" && worked[p.plan.Unless] {
			results[p.fixer.Name()] = fixJSON{Name: p.fixer.Name(), Skipped: p.plan.UnlessSkip}
			if !asJSON {
				fmt.Fprintf(out, "  %s %s: %s\n", render.Grey("–"), p.fixer.Name(), render.Grey(p.plan.UnlessSkip))
			}
			continue
		}
		// The one slow fix says so while it works.
		if !asJSON && p.fixer.Name() == "updates" {
			fmt.Fprintln(out, render.Grey("  … Installing updates. This can take a few minutes."))
		}
		rec, err := fix.Run(ctx, fixHost, store, p.fixer, p.in, p.plan)
		r := fixJSON{Name: p.fixer.Name()}
		var notKept *fix.NotKept
		switch {
		case errors.As(err, &notKept):
			// The change is made; only its undo record is missing.
			r.Result, r.Error = rec.Done, err.Error()
			worked[p.fixer.Name()] = true
			applied = append(applied, p)
			sent = append(sent, send.Fixed{ID: rec.ID, Fix: rec.Fix, Done: rec.Done, User: rec.User})
			if !asJSON {
				fmt.Fprintf(out, "  %s %s\n", render.Green("✓"), rec.Done)
				fmt.Fprintf(out, "    %s%s.\n", render.Amber("! "), strings.TrimSuffix(err.Error(), "."))
			}
		case err != nil:
			failed++
			r.Error = err.Error()
			if !asJSON {
				fmt.Fprintf(out, "  %s %s: %s. %s\n", render.Red("✗"), p.fixer.Name(), strings.TrimSuffix(err.Error(), "."), render.Grey(afterFailure(p.fixer.Name(), err)))
			}
		default:
			r.Result, r.UndoID = rec.Done, rec.ID
			worked[p.fixer.Name()] = true
			applied = append(applied, p)
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
		rescanAndSend(ctx, out, configPath, before, applied, sent, asJSON)
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

// afterFailure says what a failed fix left: nothing, when it was put back
// or never started, or what may have changed when it cannot be undone.
func afterFailure(name string, err error) string {
	var f *fix.Failed
	if errors.As(err, &f) && !f.Changed {
		return "Nothing was changed."
	}
	switch name {
	case "updates":
		return "Some updates may have installed before it stopped."
	case "certificates":
		return "Some certificates may have been renewed before it stopped."
	case "docker-cleanup":
		return "Some unused images or build cache may have been removed before it stopped."
	}
	return "Part of it may still be changed."
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
	var public, docker []int
	if ls, err := env.Listeners(); err == nil {
		for _, l := range ls {
			public = append(public, l.Port)
		}
	}
	if cs, err := env.Containers(ctx); err == nil {
		for _, c := range cs {
			for _, p := range c.Ports {
				if p.Proto == "tcp" && p.HostPort > 0 {
					docker = append(docker, p.HostPort)
				}
			}
		}
	}
	chosen := map[string]bool{}
	var out []*planned
	for _, x := range fix.All() {
		p := byName[x.Name()]
		if p == nil {
			continue
		}
		p.in.Cfg, p.in.User, p.in.Public, p.in.Docker, p.in.Planned = cfg, user, public, docker, chosen
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
	n, optional := 0, true
	for _, p := range list {
		if p.plan.Refuse == "" && p.plan.Skip == "" {
			n++
		}
		for _, f := range p.findings {
			if f.Severity != "info" {
				optional = false
			}
		}
	}
	if len(list) == 0 && len(names) > 0 {
		fmt.Fprintf(out, "%s     Nothing to fix for %s: %s.\n\n", head, strings.Join(names, ", "), passedWord(len(names)))
		return
	}
	if len(list) == 0 && r.Counts.Critical+r.Counts.Warnings == 0 {
		fmt.Fprintf(out, "%s     Nothing to fix. Lovely. ✨\n\n", head)
		return
	}
	// The grade first, and what took points off it, so it adds up before
	// anything is offered.
	fmt.Fprintln(out, head)
	printBreakdown(out, r, list)
	switch {
	case len(list) == 0:
		left := r.Counts.Critical + r.Counts.Warnings
		fmt.Fprintf(out, "  %s\n\n", render.Bold("Nothing here Kiyesi can fix by itself: "+plural(left, "finding needs", "findings need")+" a person."))
		return
	case n == 0:
		fmt.Fprintf(out, "  %s\n\n", render.Bold("Nothing Kiyesi can change safely right now."))
	case optional:
		// Nothing here moves the grade: say so, so it never reads as a problem.
		fmt.Fprintf(out, "  %s\n\n", render.Bold(fmt.Sprintf("Nothing affects the grade. %s, if you want %s:",
			plural(n, "optional clean-up", "optional clean-ups"), map[bool]string{true: "it", false: "them"}[n == 1])))
	default:
		fmt.Fprintf(out, "  %s\n\n", render.Bold(fmt.Sprintf("Kiyesi can fix %s for you:", plural(n, "thing", "things"))))
	}
	var later []*planned
	i := 0
	for _, p := range list {
		if p.plan.Refuse != "" || p.plan.Skip != "" {
			later = append(later, p)
			continue
		}
		i++
		fmt.Fprintf(out, "  %d. %s %s\n", i, render.Bold(planTitle(p)), render.Grey("("+p.fixer.Name()+")"))
		fmt.Fprintln(out, "     "+p.plan.Say)
		for _, w := range p.plan.Warn {
			fmt.Fprintln(out, "     "+render.Amber("! ")+w)
		}
		fmt.Fprintln(out)
	}
	// What Kiyesi will not do now, apart and unnumbered, so the count above
	// is the count of what it does.
	if len(later) > 0 {
		fmt.Fprintf(out, "  %s\n\n", render.Bold(fmt.Sprintf("Left to you (%d):", len(later))))
	}
	for _, p := range later {
		gain := ""
		if g := gainOf(p.findings); g > 0 {
			to := min(r.Grade.Score+g, 100)
			gain = render.Grey(fmt.Sprintf("  +%d, to %s %d, when done", g, scan.Letter(to), to))
		}
		fmt.Fprintf(out, "  • %s %s%s\n", render.Bold(planTitle(p)), render.Grey("("+p.fixer.Name()+")"), gain)
		if p.plan.Skip != "" {
			fmt.Fprintln(out, "    "+render.Grey(p.plan.Skip))
		} else {
			for _, l := range strings.Split(p.plan.Refuse, "\n") {
				fmt.Fprintln(out, "    "+l)
			}
		}
		fmt.Fprintln(out)
	}
}

// printBreakdown lists every finding that took points off the grade, worst
// first, with its points and whether Kiyesi fixes it below or leaves it to
// the person, and the sum, so the grade adds up.
func printBreakdown(out io.Writer, r scan.Report, list []*planned) {
	status := map[string]string{}
	for _, p := range list {
		tag := "Kiyesi fixes this below"
		if p.plan.Refuse != "" || p.plan.Skip != "" {
			tag = "left to you, below"
		}
		for _, f := range p.findings {
			status[f.Check+"\x00"+f.Sentence] = tag
		}
	}
	var crit, warn []string
	line := func(points string, f scan.Finding) string {
		l := "    " + points + "  " + f.Sentence
		if t := status[f.Check+"\x00"+f.Sentence]; t != "" {
			l += render.Grey("  (" + t + ")")
		}
		return l
	}
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			switch f.Severity {
			case "critical":
				crit = append(crit, line(render.Red("−15"), f))
			case "warning":
				warn = append(warn, line(render.Amber(" −5"), f))
			}
		}
	}
	if len(crit)+len(warn) == 0 {
		fmt.Fprintln(out)
		return
	}
	sum := "100"
	switch len(crit) {
	case 0:
	case 1:
		sum += " − 15"
	default:
		sum += fmt.Sprintf(" − 15 × %d", len(crit))
	}
	switch len(warn) {
	case 0:
	case 1:
		sum += " − 5"
	default:
		sum += fmt.Sprintf(" − 5 × %d", len(warn))
	}
	fmt.Fprintf(out, "\n  %s %s\n", render.Bold("What took points off:"), render.Grey(fmt.Sprintf("%s = %d", sum, r.Grade.Score)))
	for i, l := range append(crit, warn...) {
		if i == 12 {
			fmt.Fprintln(out, render.Grey(fmt.Sprintf("    and %d more", len(crit)+len(warn)-12)))
			break
		}
		fmt.Fprintln(out, l)
	}
	fmt.Fprintln(out, render.Grey("  Every finding, with its fix: sudo kiyesi scan"))
	fmt.Fprintln(out)
}

// planTitle is a fix's findings in one line, at most three.
func planTitle(p *planned) string {
	var titles []string
	for _, f := range p.findings {
		titles = append(titles, f.Sentence)
	}
	if len(titles) > 3 {
		titles = append(titles[:2], fmt.Sprintf("and %d more", len(titles)-2))
	}
	return strings.Join(titles, "; ")
}

// gainOf is how many points the grade gains when these findings go: 15 for
// each critical one and 5 for each warning, as the grade counts them.
func gainOf(fs []scan.Finding) int {
	g := 0
	for _, f := range fs {
		switch f.Severity {
		case "critical":
			g += 15
		case "warning":
			g += 5
		}
	}
	return g
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
func rescanAndSend(ctx context.Context, out io.Writer, configPath string, before scan.Report, applied []*planned, fixed []send.Fixed, quiet bool) {
	if !quiet {
		fmt.Fprintln(out, "\n"+render.Grey("  Checking again…"))
	}
	after, _, err := runScan(ctx, configPath, 0, render.ByFix)
	if err != nil {
		if !quiet {
			fmt.Fprintln(out, render.Grey("  The server could not be checked again: "+err.Error()))
		}
		return
	}
	same := after.Grade.Score == before.Grade.Score && after.Grade.Letter == before.Grade.Letter
	if !quiet && same {
		why := "unchanged"
		if onlyCleanUps(applied) {
			why = "unchanged: a clean-up does not move the grade"
		}
		fmt.Fprintf(out, "\n  %s %s %s     %s\n", render.Bold("GRADE"), render.GradeBlock(after.Grade.Letter),
			render.Bold(fmt.Sprintf("%d/100", after.Grade.Score)), render.Grey(why))
		if l := notBetter(before, after, applied); l != "" && !onlyCleanUps(applied) {
			fmt.Fprintln(out, "  "+l)
		}
		fmt.Fprintln(out)
	} else if !quiet {
		fmt.Fprintf(out, "\n  %s\n", render.GradeMove(before.Grade.Letter, before.Grade.Score, after.Grade.Letter, after.Grade.Score))
		if after.Grade.Score < before.Grade.Score {
			if l := notBetter(before, after, applied); l != "" {
				fmt.Fprintln(out, "  "+l)
			}
		}
		fmt.Fprintln(out)
	}
	if _, _, err := loadConnection(); err == nil {
		ob := send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes}
		if err := ob.Put(send.Fixes(after, time.Now(), fixed), time.Now()); err == nil && !quiet {
			fmt.Fprintln(out, render.Grey("  The dashboard shows the new grade within a minute."))
		}
	}
}

// onlyCleanUps is true when every fix made answered only optional findings.
func onlyCleanUps(applied []*planned) bool {
	if len(applied) == 0 {
		return false
	}
	for _, p := range applied {
		for _, f := range p.findings {
			if f.Severity != "info" {
				return false
			}
		}
	}
	return true
}

// notBetter names, in one short line, why the grade did not rise: findings
// a fix answered that are still there, and findings that are new.
func notBetter(before, after scan.Report, applied []*planned) string {
	aimed, had := map[string]bool{}, map[string]bool{}
	for _, p := range applied {
		for _, f := range p.findings {
			aimed[f.Sentence] = true
		}
	}
	for _, c := range before.Checks {
		for _, f := range c.Findings {
			had[f.Sentence] = true
		}
	}
	var still, fresh []string
	for _, c := range after.Checks {
		for _, f := range c.Findings {
			switch {
			case f.Severity == "info":
			case aimed[f.Sentence]:
				still = append(still, f.Sentence)
			case !had[f.Sentence]:
				fresh = append(fresh, f.Sentence)
			}
		}
	}
	short := func(s []string) string {
		if len(s) > 2 {
			return strings.Join(s[:2], "; ") + fmt.Sprintf(" and %d more", len(s)-2)
		}
		return strings.Join(s, "; ")
	}
	var parts []string
	if len(still) > 0 {
		parts = append(parts, "Still there: "+short(still)+".")
	}
	if len(fresh) > 0 {
		parts = append(parts, "New: "+short(fresh)+".")
	}
	return strings.Join(parts, " ")
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
			if r.Skipped != "" {
				j.Skipped = r.Skipped
			}
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
			"restored and the service it touched is reloaded. Three fixes cannot be\n" +
			"undone: installing updates (updates), renewing certificates (certificates)\n" +
			"and removing unused Docker images and build cache (docker-cleanup).",
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
			before, _, err := runScan(ctx, configPath, 0, render.ByUndo)
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
