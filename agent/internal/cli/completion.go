package cli

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Tab completion (PRD rule 6): `kiyesi completion bash|zsh|fish|powershell`
// prints the script, from cobra; install.sh puts it where each shell looks.
// When signed in, names are completed live from the service: servers,
// incident numbers, teammates and projects. Each lookup gets two seconds and
// gives nothing on any error, so a slow network never stops typing.

const completeWithin = 2 * time.Second

type completer func(ctx context.Context) []string

func listed(fn completer) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(context.Background(), completeWithin)
		defer cancel()
		var out []cobra.Completion
		for _, v := range fn(ctx) {
			if strings.HasPrefix(strings.ToLower(v), strings.ToLower(toComplete)) {
				out = append(out, v)
			}
		}
		sort.Strings(out)
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// onArg completes only the argument at position n, with fn; nothing after it.
func onArg(n int, fn completer) cobra.CompletionFunc {
	inner := listed(fn)
	return func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if len(args) != n {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return inner(cmd, args, toComplete)
	}
}

func serverNames(ctx context.Context) []string {
	c, err := signedIn()
	if err != nil {
		return nil
	}
	list, err := c.Servers(ctx)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.Name)
	}
	return out
}

func incidentRefs(ctx context.Context) []string {
	c, err := signedIn()
	if err != nil {
		return nil
	}
	list, err := c.Incidents(ctx, "open")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list.Incidents))
	for _, i := range list.Incidents {
		out = append(out, i.Ref)
	}
	return out
}

func teammateNames(ctx context.Context) []string {
	c, err := signedIn()
	if err != nil {
		return nil
	}
	r, err := c.Team(ctx)
	if err != nil {
		return []string{"me"}
	}
	out := []string{"me"}
	for _, p := range r.People {
		if f := strings.Fields(p.Name); len(f) > 0 && !p.You {
			out = append(out, f[0])
		}
	}
	return out
}

func projectNames(ctx context.Context) []string {
	c, err := signedIn()
	if err != nil {
		return nil
	}
	list, err := c.Projects(ctx)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.Name)
	}
	return out
}

func openTargets(ctx context.Context) []string {
	out := make([]string, 0, len(openPages))
	for p := range openPages {
		out = append(out, p)
	}
	return append(append(out, incidentRefs(ctx)...), serverNames(ctx)...)
}

func fixed(values ...string) completer {
	return func(context.Context) []string { return values }
}

// addCompletion turns on the completion command and names each argument.
func addCompletion(root *cobra.Command) {
	root.CompletionOptions.DisableDefaultCmd = false
	byServer := onArg(0, serverNames)
	byIncident := onArg(0, incidentRefs)
	for path, fn := range map[string]cobra.CompletionFunc{
		"server": byServer, "passport": byServer, "preflight": byServer, "findings": byServer, "metrics": byServer, "logs": byServer,
		"tips": byServer, "advisories": byServer,
		"servers disconnect": byServer, "servers delete": byServer, "servers reconnect": byServer,
		"servers rename": byServer, "servers restore": byServer,
		"incident": byIncident, "explain": byIncident, "ack": byIncident, "resolve": byIncident,
		"open": onArg(0, openTargets),
		"mute": func(cmd *cobra.Command, args []string, s string) ([]cobra.Completion, cobra.ShellCompDirective) {
			if len(args) == 1 {
				return listed(fixed("30m", "2h", "1d", "off"))(cmd, args, s)
			}
			return byServer(cmd, args, s)
		},
		"assign": func(cmd *cobra.Command, args []string, s string) ([]cobra.Completion, cobra.ShellCompDirective) {
			if len(args) == 1 {
				return listed(teammateNames)(cmd, args, s)
			}
			return byIncident(cmd, args, s)
		},
		"projects rename": onArg(0, projectNames), "projects delete": onArg(0, projectNames),
	} {
		if cmd, _, err := root.Find(strings.Fields(path)); err == nil && cmd != root {
			cmd.ValidArgsFunction = fn
		}
	}
	_ = root.RegisterFlagCompletionFunc("project", listed(projectNames))
	_ = root.RegisterFlagCompletionFunc("env", listed(fixed("production", "staging")))
	for _, path := range []string{"history", "deploys", "logs"} {
		if cmd, _, err := root.Find([]string{path}); err == nil && cmd.Flags().Lookup("server") != nil {
			_ = cmd.RegisterFlagCompletionFunc("server", listed(serverNames))
		}
	}
}
