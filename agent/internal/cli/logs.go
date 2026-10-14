package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// rawLines prints JSON lines in full (--raw) rather than summarised.
var rawLines bool

// followEvery is how often --follow asks for new lines.
var followEvery = 2 * time.Second

var logRanges = map[string]string{"15m": "15m", "1h": "1h", "6h": "6h", "24h": "24h", "1d": "24h", "yesterday": "24h", "7d": "7d", "week": "7d"}

func newLogs(io IO) *cobra.Command {
	var server, source, level, since, search string
	var follow, asJSON, raw bool
	var output string
	var limit int
	cmd := &cobra.Command{
		Use:   "logs [server]",
		Short: "Search the logs of your servers, or follow them live",
		Long: "Shows log lines from your servers' containers, web servers and system log,\n" +
			"oldest first. Passwords and tokens were masked on the server before they were sent.",
		Example: "  kiyesi logs --server checkout-api-prod --level error --since 1h\n" +
			"  kiyesi logs checkout-api-prod --follow\n" +
			"  kiyesi logs --search \"heap limit\" --since 24h\n" +
			"  kiyesi logs --server checkout-api-prod --since 7d --output checkout.jsonl",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if server != "" && server != args[0] {
					return usageErr("Name the server once: as kiyesi logs <server> or with --server, not both.")
				}
				server = args[0]
			}
			r, ok := logRanges[strings.ToLower(since)]
			if !ok {
				return usageErr("--since must be 15m, 1h, 6h, 24h or 7d, not %q", since)
			}
			level = strings.ToLower(level)
			if level == "warning" || level == "warnings" {
				level = "warn"
			}
			if level == "errors" {
				level = "error"
			}
			if level != "" && level != "error" && level != "warn" {
				return usageErr("--level must be error or warn (warnings and errors), not %q", level)
			}
			if limit < 1 || limit > 1000 {
				return usageErr("--limit must be from 1 to 1000")
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			q := api.LogQuery{Source: source, Level: level, Search: search, Range: r, Limit: limit}
			if server != "" {
				list, err := c.Servers(cmd.Context())
				if err != nil {
					return apiErr(err)
				}
				s, ok := find(list, server)
				if !ok {
					return usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", server)
				}
				q.ServerID = s.ID
			}
			if output != "" {
				if follow {
					return usageErr("--output saves what is there now; it cannot be used with --follow.")
				}
				return exportLogs(cmd.Context(), io, c, q, output)
			}
			page, err := c.Logs(cmd.Context(), q)
			if err != nil {
				return apiErr(err)
			}
			if asJSON && !follow {
				return render.JSON(io.Out, page)
			}
			showServer := server == ""
			rawLines = raw
			if page.Notice != nil && *page.Notice == "over_allowance" {
				fmt.Fprintln(io.Err, "Your team is over today's log allowance: new lines are counted, not kept, until tomorrow (UTC).")
			}
			if !follow {
				if len(page.Lines) == 0 {
					fmt.Fprintln(io.Out, "No lines match in that time.")
					return nil
				}
				if page.More {
					fmt.Fprintf(io.Err, "Showing the newest %d lines. Narrow the search, or use --since, for earlier ones.\n", len(page.Lines))
				}
				for _, l := range page.Lines {
					printLogLine(io, l, showServer, asJSON)
				}
				return nil
			}
			return followLogs(cmd.Context(), io, c, q, page, showServer, asJSON)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "only this server")
	cmd.Flags().StringVar(&source, "source", "", "only this container, service or file, such as checkout-api or nginx")
	cmd.Flags().StringVar(&level, "level", "", "error, or warn for warnings and errors")
	cmd.Flags().StringVar(&since, "since", "1h", "how far back: 15m, 1h, 6h, 24h or 7d")
	cmd.Flags().StringVar(&search, "search", "", "only lines with these words, in any case")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep showing new lines as they arrive, until Ctrl+C")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON (one line per log line with --follow)")
	cmd.Flags().IntVar(&limit, "limit", 300, "the most lines to show, up to 1000")
	cmd.Flags().BoolVar(&raw, "raw", false, "print JSON lines in full, rather than a short summary of each")
	cmd.Flags().StringVarP(&output, "output", "o", "", "save every matching line to this file instead: .txt, or .jsonl for JSON lines (up to 100,000 lines)")
	cmd.SetContext(context.Background())
	return cmd
}

// exportLogs saves every matching line to a file, as text or JSON lines
// by its name. The file is written beside its final name and moved into
// place only when complete, so a failed download leaves nothing half-done.
func exportLogs(ctx context.Context, io IO, c *api.Client, q api.LogQuery, path string) error {
	format := "txt"
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".ndjson", ".json":
		format = "jsonl"
	case ".txt", ".log", "":
	default:
		return usageErr("--output must end in .txt or .jsonl, not %q", filepath.Ext(path))
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kiyesi-logs-*")
	if err != nil {
		return &exitError{code: ExitUsage, msg: fmt.Sprintf("Cannot write in %s: %v", filepath.Dir(path), err)}
	}
	defer os.Remove(tmp.Name())
	if err := c.ExportLogs(ctx, q, format, tmp); err != nil {
		_ = tmp.Close()
		return apiErr(err)
	}
	info, _ := tmp.Stat()
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	fmt.Fprintf(io.Out, "Saved %s (%s).\n", path, byteSize(info.Size()))
	return nil
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// followLogs prints the lines already found, then asks every two seconds
// for new ones until Ctrl+C. Lines can reach the service a minute or two
// after they were written, so each ask looks back a little and prints only
// the lines not printed yet.
func followLogs(ctx context.Context, io IO, c *api.Client, q api.LogQuery, page api.LogPage, showServer, asJSON bool) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Each line printed, by when it was printed: the API returns a line
	// again only for a few minutes, so ten is plenty to remember it.
	seen := map[string]time.Time{}
	for _, l := range page.Lines {
		seen[l.ID] = time.Now()
		printLogLine(io, l, showServer, asJSON)
	}
	if !asJSON {
		fmt.Fprintln(io.Err, "Following new lines. Press Ctrl+C to stop.")
	}
	q.Limit = 1000
	since := time.Now()
	tick := time.NewTicker(followEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		q.Since = since
		next, err := c.Logs(ctx, q)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(io.Err, "Could not get new lines (%v); trying again.\n", err)
			continue
		}
		for _, l := range next.Lines {
			if _, ok := seen[l.ID]; ok {
				continue
			}
			seen[l.ID] = time.Now()
			printLogLine(io, l, showServer, asJSON)
		}
		// Forget lines printed long enough ago that they cannot come back.
		for id, printed := range seen {
			if time.Since(printed) > 10*time.Minute {
				delete(seen, id)
			}
		}
		since = time.Now()
	}
}

func printLogLine(io IO, l api.LogLine, showServer, asJSON bool) {
	if asJSON {
		_ = render.JSONLine(io.Out, l)
		return
	}
	level := map[string]string{"error": "ERROR", "warn": "WARN "}[l.Level]
	if level == "" {
		level = "INFO "
	}
	who := l.Source
	if showServer {
		who = l.ServerName + " " + l.Source
	}
	text := l.Text
	if s := summarize(text); s != "" && !rawLines {
		text = s
	}
	fmt.Fprintf(io.Out, "%s  %s  %s  %s\n", l.At.Local().Format("Jan 02 15:04:05"), level, who, text)
}
