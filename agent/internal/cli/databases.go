package cli

import (
	"context"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/dbwatch"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func sizeText(n *int64) string {
	if n == nil {
		return "-"
	}
	v := float64(*n)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v >= 100 || i == 0 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + " " + units[i]
}

func ofText(a, b *int64, size bool) string {
	f := func(n *int64) string {
		if n == nil {
			return "-"
		}
		if size {
			return sizeText(n)
		}
		return strconv.FormatInt(*n, 10)
	}
	if b == nil {
		return f(a)
	}
	return f(a) + " of " + f(b)
}

func newDatabases(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "databases",
		Short: "Storage, connections and slow queries for each database",
		Long: "Lists the databases Kiyesi watches: storage against its limit, connections,\n" +
			"slow queries in the last hour, the newest backup, and when it is full at the\n" +
			"rate it grows. On a server, kiyesi databases check tests the settings.",
		Example: "  kiyesi databases\n  sudo kiyesi databases check",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.Databases(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, list)
			}
			if len(list) == 0 {
				fmt.Fprintln(io.Out, "No databases watched yet. Add one to /etc/kiyesi/config.yaml on the server it runs on (or one that can reach it): see Databases in the dashboard.")
				return nil
			}
			words := map[string]string{"ok": "ok", "attention": "NEEDS ATTENTION", "critical": "CRITICAL"}
			now := time.Now()
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "DATABASE\tENGINE\tWHERE\tSTORAGE\tCONNECTIONS\tSLOW, LAST HOUR\tNEWEST BACKUP\tFULL ON\tSTATUS")
			for _, d := range list {
				where := d.Server.Name
				if d.Where == "hosted" {
					where = "hosted (read from " + d.Server.Name + ")"
				}
				slow := "-"
				if d.SlowLastHour != nil {
					slow = strconv.FormatInt(*d.SlowLastHour, 10)
				}
				backup := "-"
				if d.NewestBackupAt != nil {
					backup = ago(now.Sub(*d.NewestBackupAt)) + " ago"
				}
				full := "-"
				if d.FullAt != nil {
					full = d.FullAt.Local().Format("2 Jan 2006")
				}
				status := words[d.Status]
				if status == "ok" && d.Error != nil && *d.Error != "" {
					// An older service said ok while the database could not be read.
					status = "NEEDS ATTENTION"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Name, d.Label, where, ofText(d.SizeBytes, d.LimitBytes, true), ofText(d.Connections, d.MaxConnections, false), slow, backup, full, status)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			for _, d := range list {
				if d.Error != nil && *d.Error != "" && !unreachable(d) {
					fmt.Fprintf(io.Out, "\n%s cannot be read: %s", d.Name, *d.Error)
				}
				for _, p := range d.Problems {
					fmt.Fprintf(io.Out, "\n%s: %s", d.Name, p.Sentence)
				}
			}
			fmt.Fprintln(io.Out)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.AddCommand(newDatabasesCheck(io))
	cmd.SetContext(context.Background())
	return cmd
}

// unreachable says a problem already tells that the database cannot be read.
func unreachable(d api.Database) bool {
	for _, p := range d.Problems {
		if p.Kind == "unreachable" {
			return true
		}
	}
	return false
}

func newDatabasesCheck(io IO) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:     "check",
		Short:   "Read the databases in this server's settings now, and show what Kiyesi sees",
		Long:    "Connects to each database in the settings file with its read-only user and\nprints what the agent sends: sizes and counts, never a row, never the address.",
		Example: "  sudo kiyesi databases check",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := config.Load(configPath)
			if err != nil {
				return usageErr("%v", err)
			}
			if len(c.Databases) == 0 {
				fmt.Fprintf(io.Out, "No databases in %s. Add one:\n\n  databases:\n    - name: orders\n      url: postgres://kiyesi_ro:PASSWORD@127.0.0.1:5432/orders\n", configPath)
				return nil
			}
			r := &dbwatch.Reader{DiskBytes: diskBytes(newSystem(os.Geteuid() == 0, stateDir()))}
			failed := 0
			for _, d := range c.Databases {
				if !dbwatch.NamePattern.MatchString(d.Name) {
					fmt.Fprintf(io.Out, "%q: give it a name of letters, digits, dots and dashes.\n", d.Name)
					failed++
					continue
				}
				if _, err := dbwatch.ParseLimit(d.Limit); err != nil {
					fmt.Fprintf(io.Out, "%s: %v\n", d.Name, err)
					failed++
					continue
				}
				f := r.Read(cmd.Context(), dbwatch.Config{Name: d.Name, URL: d.URL, Limit: d.Limit, Backups: d.Backups}, time.Now())
				if f.Error != "" {
					fmt.Fprintf(io.Out, "%s: %s\n", d.Name, f.Error)
					failed++
					continue
				}
				where := "on this server"
				if f.Hosted {
					where = "hosted elsewhere"
				}
				fmt.Fprintf(io.Out, "%s: %s %s, %s. Storage %s, connections %s", d.Name, f.Engine, f.Version, where, ofText(f.SizeBytes, f.LimitBytes, true), ofText(f.Connections, f.MaxConnections, false))
				if f.SlowLastHour != nil {
					fmt.Fprintf(io.Out, ", %d slow in the last hour", *f.SlowLastHour)
				}
				if f.NewestBackupAt != "" {
					fmt.Fprintf(io.Out, ", newest backup %s", f.NewestBackupAt)
				}
				fmt.Fprintln(io.Out, ".")
			}
			if failed > 0 {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	cmd.SetContext(context.Background())
	return cmd
}

func newCosts(io IO) *cobra.Command {
	var asJSON bool
	var currency string
	cmd := &cobra.Command{
		Use:   "costs",
		Short: "Monthly cost against use, with a suggestion for each server",
		Long: "What each server costs a month, how much of it is used at its busiest, and\n" +
			"whether it is too small, larger than needed or the right size. Prices are\n" +
			"typed once in the dashboard, in the currency your provider bills in, and\n" +
			"shown in your team's currency too, at a public rate fetched once a day.",
		Example: "  kiyesi costs\n  kiyesi costs --currency EUR",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			if currency != "" && !regexp.MustCompile(`^[A-Za-z]{3}$`).MatchString(currency) {
				return usageErr("--currency is three letters, such as EUR, GBP or USD.")
			}
			out, err := c.CostList(cmd.Context(), strings.ToUpper(currency))
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, out)
			}
			money := func(v float64, cur string) string {
				return fmt.Sprintf("%s %s", cur, strconv.FormatFloat(v, 'f', -1, 64))
			}
			if w := out.RateWarning; w != nil {
				dir := "up"
				if w.Percent < 0 {
					dir = "down"
				}
				fmt.Fprintf(io.Out, "WARNING  The exchange rate moved your monthly server bill %s %.1f%% since %s,\n         from %s to %s, with no change to your servers.\n\n", dir, math.Abs(w.Percent), w.Since, money(w.From, w.Currency), money(w.To, w.Currency))
			}
			if in := out.InCurrency; in != nil && len(out.Totals) > 0 {
				line := fmt.Sprintf("Servers, each month: %s", money(in.Monthly, in.Currency))
				if in.Save > 0 {
					line += fmt.Sprintf(". You could save %s a month", money(in.Save, in.Currency))
				}
				fmt.Fprintln(io.Out, line+".")
				var billed []string
				for _, t := range out.Totals {
					billed = append(billed, money(t.Monthly, t.Currency))
				}
				fmt.Fprintf(io.Out, "As billed: %s.", strings.Join(billed, " + "))
				if out.Rate != nil {
					fmt.Fprintf(io.Out, " At the rate of %s, from %s.", out.Rate.Day, out.Rate.Source)
				}
				fmt.Fprint(io.Out, "\n\n")
				out.Totals = nil
			}
			for _, t := range out.Totals {
				line := fmt.Sprintf("Servers, each month: %s", money(t.Monthly, t.Currency))
				if t.Save > 0 {
					line += fmt.Sprintf(". You could save %s a month", money(t.Save, t.Currency))
				}
				fmt.Fprintln(io.Out, line+".")
			}
			if len(out.Totals) > 0 {
				fmt.Fprintln(io.Out)
			}
			words := map[string]string{"too_small": "TOO SMALL", "larger": "larger than needed", "right": "right size", "too_early": "too early", "no_data": "no figures"}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "SERVER\tSIZE\tA MONTH\tCPU USED\tMEMORY USED\tSUGGESTION")
			pct := func(v *float64) string {
				if v == nil {
					return "-"
				}
				return fmt.Sprintf("%.0f%%", *v)
			}
			for _, s := range out.Servers {
				price := "not set"
				if s.Price != nil {
					price = money(s.Price.Monthly, s.Price.Currency)
					if s.Converted != nil && s.Converted.Currency != s.Price.Currency {
						price += " (" + money(s.Converted.Monthly, s.Converted.Currency) + ")"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Server.Name, s.Size, price, pct(s.CPUPeak), pct(s.MemoryPeak), words[s.Suggestion.Kind])
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(io.Out)
			for _, s := range out.Servers {
				if s.Suggestion.Kind == "too_small" || s.Suggestion.Kind == "larger" {
					fmt.Fprintf(io.Out, "%s: %s\n", s.Server.Name, s.Suggestion.Sentence)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.Flags().StringVar(&currency, "currency", "", "show the costs in this currency, such as EUR or GBP")
	cmd.SetContext(context.Background())
	return cmd
}
