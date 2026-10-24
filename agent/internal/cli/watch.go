package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// kiyesi watch: a live view of what needs you, open incidents and every
// server, that refreshes in place (PRD: "A live view of all servers that
// refreshes in place"). Piped, it prints once and stops: a script never hangs.

const watchEvery = 15 * time.Second

type watchData struct {
	now       nowResult
	incidents []api.Incident
	servers   []api.Server
	at        time.Time
	err       error
}

type watchDetail struct {
	title string
	lines []string
	err   error
}

type watchTick struct{}

type watchModel struct {
	ctx       context.Context
	c         *api.Client
	dashboard string
	data      watchData
	loading   bool
	cursor    int
	detail    *watchDetail
	width     int
	clock     func() time.Time
}

// rows is what the cursor moves over: open incidents, then servers.
func (m watchModel) rows() int { return len(m.data.incidents) + len(m.data.servers) }

func (m watchModel) fetch() tea.Msg {
	ctx, cancel := context.WithTimeout(m.ctx, 20*time.Second)
	defer cancel()
	d := watchData{at: m.clock()}
	// One pass: what needs you, open incidents and servers, four requests in all.
	var lists nowLists
	d.now, lists, d.err = needsYou(ctx, m.c, d.at)
	d.incidents, d.servers = lists.incidents, lists.servers
	return d
}

func (m watchModel) Init() tea.Cmd { return m.fetch }

func (m watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case watchData:
		m.loading = false
		if msg.err != nil {
			// Keep the last good view; say what went wrong at the bottom.
			m.data.err = msg.err
		} else {
			m.data = msg
		}
		if m.cursor >= m.rows() {
			m.cursor = max(0, m.rows()-1)
		}
		return m, tea.Tick(watchEvery, func(time.Time) tea.Msg { return watchTick{} })
	case watchTick:
		m.loading = true
		return m, m.fetch
	case watchDetail:
		m.detail = &msg
		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc", "backspace", "left", "h":
			m.detail = nil
		case "up", "k":
			if m.detail == nil && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.detail == nil && m.cursor < m.rows()-1 {
				m.cursor++
			}
		case "r":
			m.loading = true
			return m, m.fetch
		case "enter", "right", "l":
			if m.detail == nil && m.rows() > 0 {
				return m, m.open()
			}
		case "o":
			if m.rows() > 0 {
				openBrowser(m.address())
			}
		}
	}
	return m, nil
}

// address is the dashboard page of the selected row.
func (m watchModel) address() string {
	if m.cursor < len(m.data.incidents) {
		return m.dashboard + "/incident/?id=" + url.QueryEscape(m.data.incidents[m.cursor].Ref)
	}
	return m.dashboard + "/server/?id=" + url.QueryEscape(m.data.servers[m.cursor-len(m.data.incidents)].ID)
}

// open loads the selected incident's evidence or server's findings.
func (m watchModel) open() tea.Cmd {
	ctx, c := m.ctx, m.c
	if m.cursor < len(m.data.incidents) {
		ref := m.data.incidents[m.cursor].Ref
		return func() tea.Msg {
			i, err := c.IncidentDetail(ctx, ref)
			if err != nil {
				return watchDetail{title: ref, err: err}
			}
			d := watchDetail{title: fmt.Sprintf("%s  %s", i.Ref, i.Title)}
			if i.Limited {
				d.lines = []string{"You can see that this incident happened and its status. The evidence is for your team."}
				return d
			}
			d.lines = append(d.lines, "Likely source: "+sourceLine(i), i.Sentence, "")
			for _, e := range i.Evidence {
				d.lines = append(d.lines, fmt.Sprintf("  %-16s %s (%s)", e.Area, e.Text, strings.ReplaceAll(e.Verdict, "_", " ")))
			}
			if i.Fix != nil {
				d.lines = append(d.lines, "", "Suggested fix: "+i.Fix.Fix)
				if i.Fix.Command != nil {
					d.lines = append(d.lines, "  "+*i.Fix.Command)
				}
			}
			d.lines = append(d.lines, whoMoved(i)...)
			if h := nextSteps(i, mayDo(ctx, c, "incidents", "act")); h != "" {
				d.lines = append(d.lines, "", h)
			}
			return d
		}
	}
	s := m.data.servers[m.cursor-len(m.data.incidents)]
	return func() tea.Msg {
		// No findings means every check passed only when there was a scan.
		switch {
		case s.Kind == "managed":
			return watchDetail{title: s.Name, lines: []string{"A managed service: Kiyesi does not scan it."}}
		case s.LastScan == nil:
			return watchDetail{title: s.Name, lines: []string{"Not scanned yet. The first scan arrives within a minute of it connecting."}}
		}
		list, err := c.Findings(ctx, "")
		if err != nil {
			return watchDetail{title: s.Name, err: err}
		}
		d := watchDetail{title: s.Name + "  findings"}
		for _, f := range list {
			if f.Server.ID == s.ID {
				first, byHand := render.FixLines(strings.TrimSpace(f.Fix), autoFixOf(f.AutoFix))
				d.lines = append(d.lines, fmt.Sprintf("%-8s %s", strings.ToUpper(f.Severity), f.Sentence), "         Fix: "+strings.ReplaceAll(first, "\n", "\n              "))
				if byHand != "" {
					d.lines = append(d.lines, "         By hand: "+strings.ReplaceAll(byHand, "\n", "\n              "))
				}
			}
		}
		if len(d.lines) == 0 {
			d.lines = []string{"No findings: every check passed on the latest scan."}
		}
		d.lines = append(d.lines, "", "kiyesi findings "+quoteArg(s.Name))
		return d
	}
}

func (m watchModel) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "kiyesi watch"
	return v
}

func (m watchModel) render() string {
	var b strings.Builder
	now := m.clock()
	status := "loading"
	if !m.data.at.IsZero() {
		status = "updated " + ago(now.Sub(m.data.at)) + " ago, every 15 s"
	}
	if m.loading {
		status += ", refreshing"
	}
	fmt.Fprintf(&b, "KIYESI WATCH  %s\n\n", status)
	if m.detail != nil {
		fmt.Fprintln(&b, m.detail.title)
		if m.detail.err != nil {
			fmt.Fprintln(&b, "Could not load it: "+m.detail.err.Error())
		}
		for _, l := range m.detail.lines {
			fmt.Fprintln(&b, l)
		}
		fmt.Fprint(&b, "\nesc back   o open in the browser   q quit\n")
		return b.String()
	}
	if len(m.data.now.Items) > 0 {
		fmt.Fprintln(&b, "NEEDS YOU NOW")
		for i, it := range m.data.now.Items {
			if i == 5 {
				fmt.Fprintf(&b, "  and %d more: kiyesi\n", len(m.data.now.Items)-5)
				break
			}
			fmt.Fprintf(&b, "  %s\n", it.Sentence)
		}
		fmt.Fprintln(&b)
	} else if !m.data.at.IsZero() {
		fmt.Fprint(&b, "Nothing needs you now.\n\n")
	}
	row := 0
	mark := func() string {
		defer func() { row++ }()
		if row == m.cursor {
			return "> "
		}
		return "  "
	}
	if len(m.data.incidents) > 0 {
		fmt.Fprintln(&b, "OPEN INCIDENTS")
		for _, i := range m.data.incidents {
			fmt.Fprintf(&b, "%s%-8s %-9s %-13s %s\n", mark(), i.Ref, i.Severity, i.Status, i.Title)
		}
		fmt.Fprintln(&b)
	}
	if len(m.data.servers) > 0 {
		fmt.Fprintf(&b, "  %-24s %-6s %-6s %-7s %-6s %-9s %s\n", "SERVER", "GRADE", "CPU", "MEMORY", "DISK", "CRITICAL", "SEEN")
		for _, s := range m.data.servers {
			cpu, mem, disk := usage(s, now)
			fmt.Fprintf(&b, "%s%-24s %-6s %-6s %-7s %-6s %-9s %s\n", mark(), cut(s.Name, 24), grade(s), cpu, mem, disk, count(s, true), seen(s, now))
		}
	} else if !m.data.at.IsZero() && m.data.now.CanAddServers {
		fmt.Fprintln(&b, "No servers yet. Add one in Settings, Add a server.")
	} else if !m.data.at.IsZero() && m.data.now.sees("servers") {
		fmt.Fprintln(&b, "No servers that you can see.")
	}
	if m.data.err != nil {
		fmt.Fprintf(&b, "\nCould not refresh: %s\n", m.data.err.Error())
	}
	fmt.Fprint(&b, "\n↑↓ choose   enter details   o open in the browser   r refresh   q quit\n")
	return b.String()
}

func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// interactive says whether both ends are a terminal a person is at.
var interactive = func(io IO) bool {
	return isTerminal(io.Out) && term.IsTerminal(os.Stdin.Fd())
}

func newWatch(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "A live view of what needs you, open incidents and every server",
		Long: "Refreshes in place every 15 seconds. Choose a row and press enter for an\n" +
			"incident's evidence or a server's findings, o to open it in the browser.\n" +
			"When the output is not a terminal, it prints the view once and stops.",
		Example: "  kiyesi watch\n  kiyesi watch --project Checkout",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			l, _ := loadLogin()
			m := watchModel{ctx: cmd.Context(), c: c, dashboard: dashboardURL(l.API), clock: time.Now}
			if !interactive(io) {
				return printWatchOnce(io.Out, m)
			}
			_, err = tea.NewProgram(m, tea.WithContext(cmd.Context())).Run()
			if err != nil && !errors.Is(err, tea.ErrProgramKilled) {
				return err
			}
			return nil
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}

func printWatchOnce(w io.Writer, m watchModel) error {
	d := m.fetch().(watchData)
	if d.err != nil {
		return apiErr(d.err)
	}
	m.data = d
	m.cursor = -1
	out := m.render()
	// The key help means nothing on paper.
	out = out[:strings.LastIndex(strings.TrimRight(out, "\n"), "\n")+1]
	_, err := fmt.Fprint(w, out)
	return err
}
