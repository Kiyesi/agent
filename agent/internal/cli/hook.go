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

	"github.com/kiyesi/kiyesi/agent/internal/githook"
	"github.com/kiyesi/kiyesi/agent/internal/pullcheck"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// hookExecutable is the kiyesi the hook will run. Tests replace it.
var hookExecutable = os.Executable

// hookNow is the time, for the list's age. Tests replace it.
var hookNow = time.Now

// hookCacheDir is where the malicious-package list is kept: KIYESI_CACHE,
// else the person's cache folder.
func hookCacheDir() (string, error) {
	if d := os.Getenv("KIYESI_CACHE"); d != "" {
		return d, nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "kiyesi"), nil
}

// hookAPI is the service the list comes from: KIYESI_API, else where the
// person signed in, else the hosted service.
func hookAPI() string {
	if v := os.Getenv("KIYESI_API"); v != "" {
		return v
	}
	if l, ok := savedLogin(); ok {
		return l.API
	}
	return DefaultAPI
}

func hookList() (*githook.List, error) {
	dir, err := hookCacheDir()
	if err != nil {
		return nil, err
	}
	return &githook.List{Dir: dir, API: hookAPI(), Now: hookNow}, nil
}

const hookLong = "A git pre-push hook that checks what each push adds, on this computer, with the\n" +
	"rules of Kiyesi's pull-request check: malicious packages, lockfile tampering,\n" +
	"hidden code, install scripts and risky workflows. It is free and needs no\n" +
	"account. A malicious package, hidden code or a tampered lockfile stops the\n" +
	"push, with the fix; install scripts and workflow advice are shown and the\n" +
	"push goes on. git push --no-verify skips the check, as it skips any hook.\n\n" +
	"The malicious-package list is kept in your cache folder and refreshed when it\n" +
	"is over 6 hours old: a push waits at most 3 seconds for an answer, and 30 for\n" +
	"a new list to arrive. Offline, the copy is used and its age is shown. Nothing from your repository is sent anywhere."

func newHook(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Check each push for malicious packages and hidden code before it leaves this computer",
		Long:  hookLong,
		Example: "  kiyesi hook install\n" +
			"  kiyesi hook status\n" +
			"  git push --no-verify     skip the check for one push",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newHookInstall(io), newHookUninstall(io), newHookStatus(io), newHookUpdate(io), newHookRun(io))
	return cmd
}

func hookCtx(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func newHookInstall(io IO) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Add Kiyesi's pre-push hook to this repository",
		Long: "Adds a pre-push hook to the repository: each git push is checked first.\n" +
			"A pre-push hook already there is kept, and runs after Kiyesi's check;\n" +
			"kiyesi hook uninstall puts it back as it was. When the repository keeps\n" +
			"its hooks in a folder of its own (core.hooksPath, as Husky sets it), nothing\n" +
			"is changed: Kiyesi prints the line to add to that hook.",
		Example: "  kiyesi hook install\n  kiyesi hook install --path ~/code/shop",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			exe, err := hookExecutable()
			if err != nil {
				return usageErr("Kiyesi could not find its own program file: %v", err)
			}
			res, err := githook.Install(hookCtx(cmd), path, exe)
			if err != nil {
				return usageErr("%v", err)
			}
			out := render.NewWriter(io.Out, io.Environ)
			switch res.Action {
			case "team":
				printTeamLine(out, res.Repo, res.LinePresent)
				installList(hookCtx(cmd), out)
				return nil
			case "unchanged":
				fmt.Fprintf(out, "Kiyesi's pre-push hook is already in %s.\n", res.Repo.Top)
			case "updated":
				fmt.Fprintf(out, "Kiyesi's pre-push hook in %s now runs %s.\n", res.Repo.Top, exe)
			default:
				fmt.Fprintf(out, "%s Each push from %s is now checked first.\n", render.Bold("Kiyesi's pre-push hook is installed."), res.Repo.Top)
			}
			fmt.Fprintln(out, render.Grey("  Hook: "+res.Hook))
			if res.Previous != "" {
				fmt.Fprintln(out, render.Grey("  The hook that was there runs after Kiyesi's check, unchanged: "+res.Previous))
			}
			if res.Repo.Shared {
				fmt.Fprintln(out, render.Grey("  This folder is core.hooksPath ("+res.Repo.HooksPath+"), so the hook checks pushes from every repository that uses it."))
			}
			fmt.Fprintln(out, render.Grey("  To skip the check for one push: git push --no-verify. To remove it: kiyesi hook uninstall"))
			installList(hookCtx(cmd), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", ".", "the repository, or any folder in it")
	return cmd
}

// printTeamLine says what to add to a hook the team keeps in the repository.
func printTeamLine(out io.Writer, r githook.Repo, present bool) {
	rel := r.TeamHook
	if p, err := filepath.Rel(r.Top, r.TeamHook); err == nil {
		rel = filepath.ToSlash(p)
	}
	if present {
		fmt.Fprintf(out, "%s already runs kiyesi hook run: each push is checked. Kiyesi changed nothing.\n", rel)
		return
	}
	fmt.Fprintf(out, "This repository keeps its hooks in %s (core.hooksPath), so Kiyesi changed nothing:\n", r.HooksPath)
	fmt.Fprintf(out, "those files are your team's, to change in a pull request. Add this line to %s,\n", rel)
	fmt.Fprintln(out, "before any other line that reads what git sends:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+githook.TeamLine)
	fmt.Fprintln(out)
	fmt.Fprintln(out, render.Grey("It checks each push where kiyesi is installed, and does nothing where it is not."))
}

func newHookUninstall(io IO) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:     "uninstall",
		Short:   "Remove Kiyesi's pre-push hook, and put back the one it kept",
		Example: "  kiyesi hook uninstall",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := githook.Uninstall(hookCtx(cmd), path)
			if err != nil {
				return usageErr("%v", err)
			}
			out := render.NewWriter(io.Out, io.Environ)
			switch res.Action {
			case "team":
				rel := res.Hook
				if p, err := filepath.Rel(res.Repo.Top, res.Hook); err == nil {
					rel = filepath.ToSlash(p)
				}
				if res.LinePresent {
					fmt.Fprintf(out, "Kiyesi changed nothing: %s is your team's. To stop the check, remove the line that runs kiyesi hook run from it.\n", rel)
				} else {
					fmt.Fprintf(out, "Kiyesi's hook is not in this repository: %s does not run it.\n", rel)
				}
			case "absent":
				fmt.Fprintf(out, "Kiyesi's pre-push hook is not in %s: nothing to remove.\n", res.Repo.Top)
			default:
				fmt.Fprintf(out, "Kiyesi's pre-push hook is removed from %s.\n", res.Repo.Top)
				if res.Previous != "" {
					fmt.Fprintln(out, render.Grey("  The hook that was there before is back, unchanged: "+res.Previous))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", ".", "the repository, or any folder in it")
	return cmd
}

// hookStatusData is kiyesi hook status --json.
type hookStatusData struct {
	githook.HookStatus
	List githook.ListState `json:"list"`
}

func newHookStatus(io IO) *cobra.Command {
	var path string
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Whether this repository's pushes are checked, and how old the malicious-package list is",
		Example: "  kiyesi hook status\n  kiyesi hook status --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := githook.Status(hookCtx(cmd), path)
			if err != nil {
				return usageErr("%v", err)
			}
			d := hookStatusData{HookStatus: s}
			if l, err := hookList(); err == nil {
				d.List = l.State()
			}
			if asJSON {
				return render.JSON(io.Out, d)
			}
			out := render.NewWriter(io.Out, io.Environ)
			switch {
			case s.Repo.Team:
				printTeamLine(out, s.Repo, s.LinePresent)
			case s.Installed:
				fmt.Fprintf(out, "%s Each push from %s is checked first.\n", render.Bold("Kiyesi's pre-push hook is installed."), s.Repo.Top)
				fmt.Fprintln(out, "  Hook:   "+s.Hook)
				runs := s.Kiyesi
				if !s.KiyesiFound {
					runs += " (not there now: kiyesi on PATH is used; run kiyesi hook install again)"
				}
				fmt.Fprintln(out, "  Runs:   "+runs)
				if s.Previous != "" {
					fmt.Fprintln(out, "  Then:   the hook that was there before, "+s.Previous)
				}
			default:
				fmt.Fprintf(out, "Kiyesi's pre-push hook is not installed in %s. To check each push: kiyesi hook install\n", s.Repo.Top)
			}
			if !s.Repo.Team {
				fmt.Fprintln(out, "  List:   "+listAge(d.List))
			} else {
				fmt.Fprintln(out, render.Grey("List: "+listAge(d.List)))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", ".", "the repository, or any folder in it")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the hook and the list as JSON, for scripts")
	return cmd
}

// listAge says how old the copy of the list is.
func listAge(st githook.ListState) string {
	if !st.Present {
		return "no malicious-package list yet: the next push, or kiyesi hook update, gets it"
	}
	s := "the malicious-package list is " + githook.Ago(hookNow().Sub(st.FetchedAt)) + " old"
	if !st.CheckedAt.IsZero() {
		s += ", checked for a newer one " + githook.Ago(hookNow().Sub(st.CheckedAt)) + " ago"
	}
	return s
}

// ageOnly is listAge after a sentence that already names the list.
func ageOnly(st githook.ListState) string {
	return strings.TrimPrefix(listAge(st), "the malicious-package list is ")
}

func newHookUpdate(io IO) *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Get the newest malicious-package list now",
		Long: "Gets the newest malicious-package list from Kiyesi, as each push does when\n" +
			"its copy is over 6 hours old. No account is needed.",
		Example: "  kiyesi hook update",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := hookList()
			if err != nil {
				return usageErr("Kiyesi has no cache folder to keep the list in: %v", err)
			}
			l.Patient = true
			st := l.Refresh(hookCtx(cmd), true)
			if st.Failed != "" {
				msg := "Kiyesi could not get the malicious-package list: " + st.Failed + "."
				if st.Present {
					msg += " The copy it has is used: " + listAge(st) + "."
				}
				return &exitError{code: ExitNoAccess, msg: msg}
			}
			fmt.Fprintf(io.Out, "The malicious-package list is current: %s.\n", ageOnly(st))
			return nil
		},
	}
}

func newHookRun(io IO) *cobra.Command {
	return &cobra.Command{
		Use:    "run <remote-name> <remote-url>",
		Short:  "Check a push (git runs this, from the pre-push hook)",
		Hidden: true,
		Args:   cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			remote := ""
			if len(args) > 0 {
				remote = args[0]
			}
			return runHook(hookCtx(cmd), io, remote)
		},
	}
}

// runHook checks a push. It stops the push (exit 1) only for a stopping
// finding: when Kiyesi itself cannot check, it says so and the push goes on.
func runHook(ctx context.Context, rw IO, remote string) error {
	out := render.NewWriter(rw.Err, rw.Environ)
	updates, err := githook.ParseUpdates(rw.In)
	if err != nil {
		fmt.Fprintln(out, "Kiyesi did not check this push: "+err.Error())
		return nil
	}
	pushed := false
	for _, u := range updates {
		if strings.Trim(u.LocalSHA, "0") != "" {
			pushed = true
		}
	}
	if !pushed {
		return nil
	}
	listPath := ""
	var listNote string
	if l, err := hookList(); err != nil {
		listNote = "Kiyesi has no cache folder for the malicious-package list, so packages were not checked against it."
	} else {
		st := l.Refresh(ctx, false)
		if st.Present {
			listPath = st.Path
			if st.Failed != "" {
				listNote = fmt.Sprintf("The malicious-package list is %s old: %s.", githook.Ago(hookNow().Sub(st.FetchedAt)), whyNoList(st.Failed))
			}
		} else {
			listNote = "Kiyesi has no copy of the malicious-package list yet (" + whyNoList(st.Failed) + "), so packages were not checked against it. The other rules ran."
		}
	}
	rep := githook.CheckPush(ctx, ".", remote, updates, listPath)
	printPush(out, rep, listNote)
	if rep.Stop {
		return &exitError{code: ExitFindings}
	}
	return nil
}

// installList gets the malicious-package list as the hook is installed, so
// the first push does not wait for it. Its trouble never fails the install:
// each push tries again.
func installList(ctx context.Context, out io.Writer) {
	l, err := hookList()
	if err != nil {
		return
	}
	l.Patient = true
	st := l.Refresh(ctx, !l.State().Present)
	switch {
	case st.Present && st.Failed == "":
		fmt.Fprintln(out, render.Grey("  The malicious-package list is ready: "+ageOnly(st)+"."))
	case st.Present:
		fmt.Fprintln(out, render.Grey("  The malicious-package list is "+githook.Ago(hookNow().Sub(st.FetchedAt))+" old: "+whyNoList(st.Failed)+". Each push tries again."))
	default:
		fmt.Fprintln(out, "Kiyesi could not get the malicious-package list yet ("+whyNoList(st.Failed)+"). Until it has it, packages are not checked against it. Each push tries again, or run: kiyesi hook update")
	}
}

func whyNoList(failed string) string {
	switch {
	case failed == "":
		return "Kiyesi could not get it"
	case strings.HasPrefix(failed, "could not reach"):
		return "Kiyesi could not reach the internet"
	case strings.HasPrefix(failed, "no answer"), strings.HasPrefix(failed, "the list did not arrive"):
		return failed + "; kiyesi hook update waits longer"
	default:
		return "Kiyesi could not get a newer one: " + failed
	}
}

// printPush prints a push's findings for the person pushing, on git's screen.
func printPush(w io.Writer, rep githook.Report, listNote string) {
	var stops, warns []pullcheck.Finding
	for _, f := range rep.Findings {
		if githook.Stops(f) {
			stops = append(stops, f)
		} else {
			warns = append(warns, f)
		}
	}
	switch {
	case len(stops) > 0:
		fmt.Fprintf(w, "\n%s %s\n", render.Red("✗"), render.Bold("Kiyesi stopped this push: "+hookCount(len(stops), "problem")+" to fix first."))
	case len(warns) > 0:
		fmt.Fprintf(w, "\n%s %s\n", render.Amber("!"), render.Bold("Kiyesi checked this push: "+hookCount(len(warns), "warning")+", which do not stop it."))
	default:
		fmt.Fprintln(w, render.Grey("Kiyesi checked this push: nothing found."))
	}
	for _, f := range stops {
		printFinding(w, f, render.Red("STOP"))
	}
	for _, f := range warns {
		printFinding(w, f, render.Amber("WARN"))
	}
	var notes []string
	for _, n := range rep.Notes {
		// The list's date is said only when it matters, below.
		if strings.HasPrefix(n, "The malicious-package list is from ") || strings.HasPrefix(n, "The malicious-package list is missing") {
			continue
		}
		notes = append(notes, n)
	}
	if listNote != "" {
		notes = append(notes, listNote)
	}
	if n := len(rep.Skipped); n > 0 {
		var parts []string
		for i, s := range rep.Skipped {
			if i == 5 {
				parts = append(parts, fmt.Sprintf("and %d more", n-5))
				break
			}
			parts = append(parts, s.Path+" ("+s.Why+")")
		}
		notes = append(notes, "Not read: "+strings.Join(parts, ", ")+".")
	}
	if len(rep.Findings) > 0 && len(notes) > 0 {
		fmt.Fprintln(w)
	}
	for _, n := range notes {
		fmt.Fprintln(w, render.Grey(n))
	}
	if len(stops) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Fix the problems above, commit, and push again.")
		fmt.Fprintln(w, "To push anyway, skipping this check: git push --no-verify")
		fmt.Fprintln(w)
	} else if len(warns) > 0 {
		fmt.Fprintln(w)
	}
}

func hookCount(n int, s string) string {
	if n == 1 {
		return "1 " + s
	}
	return fmt.Sprintf("%d %ss", n, s)
}

// printFinding prints one finding: what, where, the line, how and the fix.
func printFinding(w io.Writer, f pullcheck.Finding, mark string) {
	fmt.Fprintf(w, "\n  %s  %s\n", mark, render.Bold(f.Title))
	where := f.File
	if f.Start > 0 {
		where = fmt.Sprintf("%s:%d", f.File, f.Start)
	}
	fmt.Fprintln(w, "        "+render.Grey(where))
	if f.Snippet != "" {
		lines := strings.Split(strings.TrimRight(f.Snippet, "\n"), "\n")
		if len(lines) > 6 {
			lines = append(lines[:6], "…")
		}
		for _, l := range lines {
			fmt.Fprintln(w, "        "+render.Grey("│ ")+strings.TrimRight(l, "\r"))
		}
	}
	if f.How != "" {
		fmt.Fprintln(w, "        Why: "+f.How)
	}
	if f.Fix != "" {
		fmt.Fprintln(w, "        "+render.Bold("Fix:")+" "+f.Fix)
	}
}
