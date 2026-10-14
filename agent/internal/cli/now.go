package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// What needs you now, as `kiyesi` alone prints it (PRD: "Show what needs
// you now and suggest the next command"). The sentences are the dashboard's
// Needs you now card, word for word, with open incidents and your own work
// first, since the terminal is where incidents get handled.
type nowItem struct {
	Kind     string `json:"kind"`
	Sentence string `json:"sentence"`
	Command  string `json:"command"`
}

type nowResult struct {
	Items   []nowItem `json:"items"`
	Next    string    `json:"next"`
	Servers int       `json:"servers"`
	// The team's calm streak: its shortest server streak, in days.
	CalmDays *int `json:"calmDays,omitempty"`
}

func runNow(io IO, asJSON bool, ctx context.Context) error {
	c, err := signedIn()
	if err != nil {
		if asJSON {
			return err
		}
		fmt.Fprintln(io.Out, "You are not signed in here.")
		fmt.Fprintln(io.Out, "On a server:  sudo kiyesi scan   prints its report; nothing leaves the server.")
		fmt.Fprintln(io.Out, "To see your team's servers and incidents:  kiyesi login")
		return nil
	}
	r, err := whatNeedsYou(ctx, c, time.Now())
	if err != nil {
		return apiErr(err)
	}
	if asJSON {
		return render.JSON(io.Out, r)
	}
	printNow(io.Out, r)
	return nil
}

var incidentTitle = regexp.MustCompile(`^(INC-\d+): (.*)$`)

// hidden is an answer that only means the person's role does not see that area.
func hidden(err error) bool { return errors.Is(err, api.ErrNotFound) }

func whatNeedsYou(ctx context.Context, c *api.Client, now time.Time) (nowResult, error) {
	r, _, err := needsYou(ctx, c, now)
	return r, err
}

// nowLists is what needsYou read on the way, so kiyesi watch shows it
// without asking the service again.
type nowLists struct {
	incidents []api.Incident
	servers   []api.Server
}

func needsYou(ctx context.Context, c *api.Client, now time.Time) (nowResult, nowLists, error) {
	var r nowResult
	var lists nowLists
	seen := map[string]bool{}
	add := func(kind, key, sentence, command string) {
		if key != "" && seen[key] {
			return
		}
		seen[key] = true
		r.Items = append(r.Items, nowItem{Kind: kind, Sentence: sentence, Command: command})
	}

	incidents, err := c.Incidents(ctx, "open")
	if err != nil && !hidden(err) {
		return r, lists, err
	}
	lists.incidents = incidents.Incidents
	// Critical and nobody on it first, then the rest of what is open.
	for _, pass := range []func(api.Incident) bool{
		func(i api.Incident) bool { return i.Severity == "critical" && i.Status == "open" },
		func(api.Incident) bool { return true },
	} {
		for _, i := range incidents.Incidents {
			if !pass(i) {
				continue
			}
			s := fmt.Sprintf("%s is open: %s.", i.Ref, strings.TrimSuffix(i.Title, "."))
			if i.Status == "open" {
				s += " Nobody has acknowledged it."
			}
			add("incident", i.Ref, s, "kiyesi incident "+i.Ref)
		}
	}

	work, err := c.Work(ctx, "mine")
	if err != nil && !hidden(err) {
		return r, lists, err
	}
	for _, p := range work.People {
		if !p.You {
			continue
		}
		for _, w := range p.Items {
			if w.State == "fixed" {
				continue
			}
			// An incident's title starts with its number: "INC-11: storefront-web ...".
			if m := incidentTitle.FindStringSubmatch(w.Title); w.Kind == "incident" && m != nil {
				add("work", m[1], fmt.Sprintf("%s is yours: %s.", m[1], strings.TrimSuffix(m[2], ".")), "kiyesi incident "+m[1])
				continue
			}
			add("work", w.Key, fmt.Sprintf("Given to you: %s.", strings.TrimSuffix(w.Title, ".")), "kiyesi mine")
		}
	}

	checks, err := c.Uptime(ctx)
	if err != nil && !hidden(err) {
		return r, lists, err
	}
	for _, u := range checks {
		if u.Status == "down" {
			add("site", "site:"+u.ID, fmt.Sprintf("%s is not answering.", u.Name), "kiyesi uptime")
		}
	}

	servers, err := c.Servers(ctx)
	if err != nil && !hidden(err) {
		return r, lists, err
	}
	lists.servers = servers
	r.Servers = len(servers)
	for _, s := range servers {
		if s.Calm != nil && (r.CalmDays == nil || s.Calm.Days < *r.CalmDays) {
			d := s.Calm.Days
			r.CalmDays = &d
		}
	}
	for _, s := range servers {
		if s.Silent && s.LastSeenAt != nil {
			add("silent", "silent:"+s.ID, fmt.Sprintf("%s has not reported for %s.", s.Name, ago(now.Sub(*s.LastSeenAt))), "kiyesi server "+quoteArg(s.Name))
		}
	}
	for _, s := range servers {
		if s.LastScan != nil && s.LastScan.Counts.Critical > 0 {
			n := s.LastScan.Counts.Critical
			what := "a critical finding"
			if n > 1 {
				what = fmt.Sprintf("%d critical findings", n)
			}
			add("critical", "critical:"+s.ID, fmt.Sprintf("%s has %s.", s.Name, what), "kiyesi findings "+quoteArg(s.Name))
		}
	}

	switch {
	case len(r.Items) > 0:
		r.Next = r.Items[0].Command
	case r.Servers == 0:
		r.Next = "kiyesi open settings"
	default:
		r.Next = "kiyesi servers"
	}
	return r, lists, nil
}

func printNow(w io.Writer, r nowResult) {
	switch {
	case len(r.Items) == 0 && r.Servers == 0:
		fmt.Fprintln(w, "No servers yet. Add one in Settings, Add a server: it shows the two commands to run on it.")
	case len(r.Items) == 0:
		fmt.Fprintf(w, "Nothing needs you now: %s, all reporting, no critical findings, no open incidents.\n", plural(r.Servers, "server", "servers"))
	default:
		fmt.Fprintln(w, "NEEDS YOU NOW")
		for _, i := range r.Items {
			fmt.Fprintf(w, "  %s\n      %s\n", i.Sentence, i.Command)
		}
	}
	if r.CalmDays != nil && *r.CalmDays > 0 {
		fmt.Fprintf(w, "Calm streak: %s without a critical finding on any server.\n", plural(*r.CalmDays, "day", "days"))
	}
	fmt.Fprintf(w, "\nNext: %s\n", r.Next)
}

// quoteArg quotes a name with spaces, so the suggested command can be pasted.
func quoteArg(s string) string {
	if strings.ContainsAny(s, " \t'\"") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
