// Package cli holds the commands, one file each, built on cobra. Every
// command prints plain text by default and data with --json, never asks a
// question, and exits with a code that means something.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// Exit codes, from the Development guide.
const (
	ExitOK       = 0 // fine
	ExitFindings = 1 // findings you asked it to fail on, or a "wait" answer
	ExitUsage    = 2 // a mistake in the command or the settings
	ExitNoAccess = 3 // cannot reach the service, or not allowed
)

// exitError carries an exit code and a message that says what to do next.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func usageErr(format string, a ...any) error {
	return &exitError{code: ExitUsage, msg: fmt.Sprintf(format, a...)}
}

// IO is where a command reads its environment and writes its output.
type IO struct {
	Out, Err io.Writer
	Environ  []string
	// In is where answers to questions are read, such as a two-step code.
	In io.Reader
}

// Execute runs the command line and returns the exit code.
func Execute(args []string, io IO) int {
	// The watchful dot, for a person at a terminal: it goes before anything is printed.
	spin := newSpinner(io)
	if spin != nil {
		io.Out, io.Err = spin.guard(io.Out), spin.guard(io.Err)
	}
	defer spin.stop()
	root := newRoot(io)
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) { spin.spinFor(cmd, args) }
	root.SetArgs(args)
	err := root.Execute()
	spin.stop()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(io.Err, ee.msg)
		}
		return ee.code
	}
	// cobra's own errors are mistakes in the command: unknown flag, bad value.
	fmt.Fprintf(io.Err, "%v\nRun kiyesi --help to see the commands and their options.\n", err)
	return ExitUsage
}

func newRoot(io IO) *cobra.Command {
	root := &cobra.Command{
		Use:   "kiyesi",
		Short: "Server health and security, with the fix for every problem",
		Long: "Kiyesi checks a Linux server's health and security and prints each problem\n" +
			"in one sentence with the command that fixes it. The scan and the agent only\n" +
			"read: they never change a file, a setting or a container. Only sudo kiyesi fix,\n" +
			"which you run and answer yourself, makes a change, and most can be undone.\n\n" +
			"Alone, kiyesi shows what needs you now and the next command to run.",
		Example:       "  kiyesi              what needs you now, and the next command\n  sudo kiyesi scan    this server's report; nothing leaves it",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var nowJSON bool
	root.Flags().BoolVar(&nowJSON, "json", false, "print what needs you now as JSON, for scripts")
	root.RunE = func(cmd *cobra.Command, _ []string) error {
		return runNow(io, nowJSON, cmd.Context())
	}
	root.SetOut(io.Out)
	root.SetErr(io.Err)
	// The company line at the foot of kiyesi --help only, not every command's help.
	root.SetHelpTemplate(root.HelpTemplate() + `{{if not .HasParent}}
` + copyright() + `
{{end}}`)
	listFilter.project, listFilter.env = "", ""
	root.PersistentFlags().StringVar(&listFilter.project, "project", "", "show only this project, by name, in any list")
	root.PersistentFlags().StringVar(&listFilter.env, "env", "", "show only production or staging, in any list")
	root.AddCommand(newScan(io), newFix(io), newConnect(io), newAgent(io), newLogin(io), newLogout(io), newServers(io), newServer(io), newAlerts(io), newMute(io), newUptime(io), newMetrics(io), newHistory(io), newLogs(io), newErrors(io), newTraces(io), newTrace(io), newIncidents(io), newIncident(io), newAck(io), newResolve(io), newMine(io), newAssign(io), newTeam(io), newActivity(io), newWhoami(io), newRun(io), newJobs(io), newDatabases(io), newCosts(io), newSourcemaps(io), newDeploy(io), newUninstall(io), newDeploys(io), newPlatforms(io), newDatamap(io), newTips(io), newAdvisories(io), newStatus(io), newReports(io), newReport(io), newProjects(io), newSessions(io), newCredit(io), newFindings(io), newOpen(io), newUpdate(io), newWatch(io), newPreflight(io), newExplain(io), newDrill(io), newPassport(io), newBadge(io), newVersion(io))
	addCompletion(root)
	return root
}

// Main runs the command line for the real process.
func Main() {
	os.Exit(Execute(os.Args[1:], IO{Out: os.Stdout, Err: os.Stderr, Environ: os.Environ(), In: os.Stdin}))
}

// jsonOut prints a list as JSON for --json: [] when it is empty, never null.
func jsonOut[T any](w io.Writer, list []T) error {
	if list == nil {
		list = []T{}
	}
	return render.JSON(w, list)
}
