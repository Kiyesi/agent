package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Commands that only do something, and print a sentence saying it is done,
// or that stream or hand over something other than data. Every other command
// prints data and must offer --json (PRD, rules for every command: 1).
var actionOnly = map[string]string{
	"kiyesi ack":                   "acknowledges",
	"kiyesi resolve":               "marks fixed",
	"kiyesi assign":                "gives work to someone",
	"kiyesi mute":                  "silences a server",
	"kiyesi login":                 "signs in",
	"kiyesi logout":                "signs out",
	"kiyesi connect":               "links this server",
	"kiyesi uninstall":             "removes the agent",
	"kiyesi agent":                 "runs the agent service",
	"kiyesi mcp":                   "speaks only JSON-RPC, to an AI assistant",
	"kiyesi run":                   "wraps a job",
	"kiyesi deploy":                "marks a deploy",
	"kiyesi deploys remove":        "removes a deploy",
	"kiyesi open":                  "opens the browser",
	"kiyesi credit topup":          "opens the browser",
	"kiyesi alerts test":           "sends test messages",
	"kiyesi uptime add":            "adds a check",
	"kiyesi uptime edit":           "changes a check",
	"kiyesi servers delete":        "deletes a server",
	"kiyesi servers disconnect":    "disconnects a server",
	"kiyesi servers reconnect":     "prints a new token, once, to copy",
	"kiyesi servers rename":        "renames a server",
	"kiyesi servers restore":       "restores a server",
	"kiyesi projects delete":       "deletes a project",
	"kiyesi projects rename":       "renames a project",
	"kiyesi sessions end":          "ends sign-ins",
	"kiyesi sourcemaps":            "only groups upload",
	"kiyesi sourcemaps upload":     "uploads files",
	"kiyesi status post":           "posts an update",
	"kiyesi team access":           "changes access",
	"kiyesi team invite":           "invites someone",
	"kiyesi team leave":            "leaves the team",
	"kiyesi team use":              "chooses a team",
	"kiyesi databases check":       "checks one connection on this server",
	"kiyesi report":                "makes a report and saves it or its link",
	"kiyesi update":                "replaces the program",
	"kiyesi watch":                 "a live view; kiyesi servers --json is its data",
	"kiyesi completion":            "prints a shell script",
	"kiyesi completion bash":       "prints a shell script",
	"kiyesi completion zsh":        "prints a shell script",
	"kiyesi completion fish":       "prints a shell script",
	"kiyesi completion powershell": "prints a shell script",
	"kiyesi help":                  "cobra's help",
}

func TestEveryCommandThatPrintsDataHasJSON(t *testing.T) {
	var walk func(c *cobra.Command)
	var missing []string
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		if _, ok := actionOnly[path]; !ok && c.Runnable() && c.Flags().Lookup("json") == nil {
			missing = append(missing, path)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot(IO{}))
	if len(missing) > 0 {
		t.Errorf("these commands print data but have no --json:\n  %s", strings.Join(missing, "\n  "))
	}
}
