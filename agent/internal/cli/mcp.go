package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// kiyesi mcp: an MCP server on this computer, so a person's own AI assistant
// (Claude, Cursor, VS Code, Windsurf…) can read Kiyesi with that person's
// login and role. It only reads: every tool is a question, and the service
// refuses anything else from it. It answers only when an owner allowed AI
// assistants for the team. Kiyesi itself never sends data to an AI.
//
// The protocol is JSON-RPC 2.0, one message a line on standard input and
// output (the MCP stdio transport), written here rather than taken from a
// library, as the agent must stay small.

func newMCP(io IO) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Let your own AI assistant read Kiyesi, with your access (an MCP server)",
		Long: "Runs an MCP server on this computer for an AI assistant such as Claude, Cursor,\n" +
			"VS Code or Windsurf. It answers from Kiyesi with your login and your role, and\n" +
			"only reads: servers, findings, incidents, alerts, logs, metrics, history and\n" +
			"uptime. An owner must first allow AI assistants for the team, in the dashboard:\n" +
			"Team and security, AI assistants. Your assistant starts it; you do not run it\n" +
			"by hand. Sign in first with kiyesi login.",
		Example: "  claude mcp add kiyesi -- kiyesi mcp\n" +
			"  # Cursor, VS Code and others: a server named kiyesi, command kiyesi, argument mcp",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			c.Via = "mcp"
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			in := io.In
			if in == nil {
				in = os.Stdin
			}
			return serveMCP(ctx, in, io.Out, c)
		},
	}
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// The protocol versions this server speaks; the newest is offered when a
// client asks for one it does not know.
var mcpVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// serveMCP answers one message a line until standard input ends.
func serveMCP(ctx context.Context, in io.Reader, out io.Writer, c *api.Client) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m rpcMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil || m.Method == "" {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": rpcError{-32700, "Not a JSON-RPC message."}})
			continue
		}
		// A notification wants no answer.
		if len(m.ID) == 0 || string(m.ID) == "null" {
			continue
		}
		result, rerr := handleMCP(ctx, c, m)
		reply := map[string]any{"jsonrpc": "2.0", "id": m.ID}
		if rerr != nil {
			reply["error"] = rerr
		} else {
			reply["result"] = result
		}
		if err := enc.Encode(reply); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return sc.Err()
}

func handleMCP(ctx context.Context, c *api.Client, m rpcMessage) (any, *rpcError) {
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		v := mcpVersions[0]
		for _, known := range mcpVersions {
			if p.ProtocolVersion == known {
				v = known
			}
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "kiyesi", "title": "Kiyesi", "version": version.Version},
			"instructions": "Kiyesi watches Linux servers and apps: grades, findings with their fixes, incidents, alerts, logs, " +
				"metrics, history and uptime. Every tool only reads, with the signed-in person's access. Quote fixes exactly " +
				"as given; never invent a command. Start with servers or findings.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools()}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return nil, &rpcError{-32602, "The tool call could not be read."}
		}
		text, err := callTool(ctx, c, p.Name, p.Arguments)
		if err != nil {
			return map[string]any{"content": []map[string]any{{"type": "text", "text": mcpErrorText(err)}}, "isError": true}, nil
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": false}, nil
	}
	return nil, &rpcError{-32601, "Kiyesi does not know " + m.Method + "."}
}

// mcpErrorText says what went wrong in words an assistant can pass on.
func mcpErrorText(err error) string {
	switch {
	case errors.Is(err, api.ErrSignedOut):
		return "Kiyesi is signed out on this computer. Run kiyesi login in a terminal, then ask again."
	case errors.Is(err, api.ErrNotFound):
		return err.Error()
	}
	return err.Error()
}

type mcpTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`
}

func schema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(desc string, enum ...string) map[string]any {
	p := map[string]any{"type": "string", "description": desc}
	if len(enum) > 0 {
		p["enum"] = enum
	}
	return p
}

func mcpTools() []mcpTool {
	ro := map[string]any{"readOnlyHint": true, "openWorldHint": false}
	server := prop("A server's name, as kiyesi servers lists it.")
	return []mcpTool{
		{"servers", "Servers", "Every server you can see: its grade, its critical findings and warnings, and whether it is reporting.", schema(map[string]any{}), ro},
		{"server", "One server", "One server's latest scan: grade, each finding with why it matters and its exact fix, and where its data is.", schema(map[string]any{"name": server}, "name"), ro},
		{"findings", "Findings", "Open findings on every server, critical first, each with its fix.", schema(map[string]any{"severity": prop("Only this level.", "critical", "warning")}), ro},
		{"incidents", "Incidents", "Incidents, with their likely source and how sure Kiyesi is.", schema(map[string]any{"status": prop("Which incidents. Default: open.", "open", "fixed", "all")}), ro},
		{"incident", "One incident", "One incident in full: its evidence, timeline and suggested fix.", schema(map[string]any{"ref": prop("Its reference, such as INC-14.")}, "ref"), ro},
		{"alerts", "Open alerts", "Alerts open now: what is wrong, where, and since when.", schema(map[string]any{}), ro},
		{"logs", "Search logs", "Log lines, newest first, with passwords and tokens already masked.", schema(map[string]any{
			"search": prop("Words to find."), "server": server,
			"level": prop("Only this level or worse: error, or warning (warnings and errors).", "error", "warning"),
			"range": prop("How far back. Default: 1h.", "15m", "1h", "24h", "7d"),
		}), ro},
		{"metrics", "Metrics", "One server's CPU, memory, disk and requests over a range, summed up as lowest, average, highest and latest.", schema(map[string]any{
			"name": server, "range": prop("How far back. Default: 24h.", "1h", "24h", "7d", "30d"),
		}, "name"), ro},
		{"history", "History", "What happened, newest first: deploys, grade changes, restarts, memory kills, sites down, fixes and sign-ins.", schema(map[string]any{
			"server": server, "since": prop("How far back. Default: 24h.", "1h", "24h", "7d", "30d", "90d"),
		}), ro},
		{"uptime", "Uptime", "Each site checked from outside: up or down, and how fast it answers.", schema(map[string]any{}), ro},
	}
}

func argString(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func oneOf(v string, allowed ...string) (string, error) {
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("%q is not one of %s", v, strings.Join(allowed, ", "))
}

// callTool runs one tool and returns its answer as JSON text.
func callTool(ctx context.Context, c *api.Client, name string, args map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out any
	var err error
	serverID := func(key string) (string, error) {
		n := argString(args, key, "")
		if n == "" {
			return "", fmt.Errorf("say which server: %s", key)
		}
		list, err := c.Servers(ctx)
		if err != nil {
			return "", err
		}
		s, ok := find(list, n)
		if !ok {
			return "", fmt.Errorf("there is no server called %q that you can see", n)
		}
		return s.ID, nil
	}
	switch name {
	case "servers":
		out, err = c.Servers(ctx)
	case "server":
		var id string
		if id, err = serverID("name"); err == nil {
			out, err = c.Server(ctx, id)
		}
	case "findings":
		sev := argString(args, "severity", "")
		if sev != "" {
			if sev, err = oneOf(sev, "critical", "warning"); err != nil {
				return "", err
			}
		}
		out, err = c.Findings(ctx, sev)
	case "incidents":
		var status string
		if status, err = oneOf(argString(args, "status", "open"), "open", "fixed", "all"); err == nil {
			out, err = c.Incidents(ctx, status)
		}
	case "incident":
		ref := argString(args, "ref", "")
		if ref == "" {
			return "", errors.New("say which incident: ref, such as INC-14")
		}
		out, err = c.IncidentDetail(ctx, ref)
	case "alerts":
		out, err = c.OpenAlerts(ctx)
	case "logs":
		q := api.LogQuery{Search: argString(args, "search", ""), Limit: 200}
		if q.Range, err = oneOf(argString(args, "range", "1h"), "15m", "1h", "24h", "7d"); err != nil {
			return "", err
		}
		if lv := argString(args, "level", ""); lv != "" {
			if q.Level, err = oneOf(lv, "error", "warning"); err != nil {
				return "", err
			}
			if q.Level == "warning" {
				q.Level = "warn" // the service's word
			}
		}
		if argString(args, "server", "") != "" {
			if q.ServerID, err = serverID("server"); err != nil {
				return "", err
			}
		}
		out, err = c.Logs(ctx, q)
	case "metrics":
		var id, rng string
		if rng, err = oneOf(argString(args, "range", "24h"), "1h", "24h", "7d", "30d"); err != nil {
			return "", err
		}
		if id, err = serverID("name"); err == nil {
			var ch api.Charts
			if ch, err = c.Metrics(ctx, id, rng); err == nil {
				out = summarizeCharts(ch, rng)
			}
		}
	case "history":
		var since, id string
		if since, err = oneOf(argString(args, "since", "24h"), "1h", "24h", "7d", "30d", "90d"); err != nil {
			return "", err
		}
		if argString(args, "server", "") != "" {
			if id, err = serverID("server"); err != nil {
				return "", err
			}
		}
		out, err = c.History(ctx, since, id, "")
	case "uptime":
		out, err = c.Uptime(ctx)
	default:
		return "", fmt.Errorf("there is no tool called %q", name)
	}
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// seriesSummary is a series as an assistant needs it: not every point.
type seriesSummary struct {
	Lowest  float64 `json:"lowest"`
	Average float64 `json:"average"`
	Highest float64 `json:"highest"`
	Latest  float64 `json:"latest"`
}

func sumUp(points [][2]float64) *seriesSummary {
	if len(points) == 0 {
		return nil
	}
	s := seriesSummary{Lowest: math.Inf(1), Highest: math.Inf(-1)}
	sum := 0.0
	for _, p := range points {
		v := p[1]
		s.Lowest, s.Highest = math.Min(s.Lowest, v), math.Max(s.Highest, v)
		sum += v
	}
	round := func(v float64) float64 { return math.Round(v*10) / 10 }
	s.Average, s.Lowest, s.Highest, s.Latest = round(sum/float64(len(points))), round(s.Lowest), round(s.Highest), round(points[len(points)-1][1])
	return &s
}

func summarizeCharts(ch api.Charts, rng string) map[string]any {
	disks := map[string]*seriesSummary{}
	mounts := make([]string, 0, len(ch.Disk))
	for m := range ch.Disk {
		mounts = append(mounts, m)
	}
	sort.Strings(mounts)
	for _, m := range mounts {
		disks[m] = sumUp(ch.Disk[m])
	}
	deploys := make([]string, 0, len(ch.Deploys))
	for _, d := range ch.Deploys {
		deploys = append(deploys, d.At.UTC().Format(time.RFC3339)+" "+d.Title)
	}
	return map[string]any{
		"range":               rng,
		"cpu_percent":         sumUp(ch.CPU),
		"memory_percent":      sumUp(ch.Memory),
		"disk_percent":        disks,
		"requests_per_minute": sumUp(ch.Requests),
		"errors_per_minute":   sumUp(ch.Errors),
		"p95_ms":              sumUp(ch.P95),
		"deploys":             deploys,
	}
}
