package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// BreakInDetail is what kiyesi breach-check adds to the check's own result.
type BreakInDetail struct {
	// Signs is how many kinds of sign were looked for.
	Signs int
	// Below are lines printed under a finding, by its place in the list,
	// such as the sign-ins around the time login keys changed.
	Below map[int][]string
	// Life is the end-of-life check's result, shown under the header:
	// whether the system still gets security fixes, and until when.
	Life []scan.CheckResult
}

// BreakIn prints kiyesi breach-check's answer: no signs, or each sign with
// what it means and what to do, most serious first, and what to do now
// when anything points to a break-in.
func BreakIn(w io.Writer, r scan.Report, d BreakInDetail) error {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line("")
	line(grey.Render(fmt.Sprintf("Kiyesi %s · break-in check · nothing leaves this server", version.Version)))
	line(grey.Render(breachHostLine(r, d.Signs)))
	if l := breachLifeLine(d.Life); l != "" {
		line(l)
	}
	line("")
	if len(r.Checks) == 0 {
		return fmt.Errorf("the check did not run")
	}
	c := r.Checks[0]
	switch c.Status {
	case "skip":
		line(amberB.Render("Not checked: ") + c.SkipReason)
	case "pass":
		line(green.Bold(true).Render("No signs of a break-in"))
		line("")
		for _, l := range wrap("Checked: system programs against their packages, running programs, what starts by itself (cron, systemd, rc.local), accounts, login keys, preloaded libraries, shell history and the sign-in log.", fixWidth+5, 0) {
			line(grey.Render(l))
		}
	default:
		type item struct {
			f scan.Finding
			i int
		}
		var crit, warn, info []item
		for i, f := range c.Findings {
			switch f.Severity {
			case "critical":
				crit = append(crit, item{f, i})
			case "warning":
				warn = append(warn, item{f, i})
			default:
				info = append(info, item{f, i})
			}
		}
		line(breachSummary(len(crit), len(warn), len(info)))
		line("")
		each := func(mark string, list []item) {
			for _, it := range list {
				line(" " + mark + "  " + it.f.Sentence)
				for _, l := range wrap(it.f.Why, fixWidth, 0) {
					line("       " + grey.Render(l))
				}
				for _, l := range wrap("Fix: "+it.f.Fix, fixWidth, 5) {
					line("       " + l)
				}
				for _, l := range d.Below[it.i] {
					line("       " + l)
				}
				line("")
			}
		}
		each(red.Render("SIGN"), crit)
		each(amber.Render("LOOK"), warn)
		each(grey.Render("NOTE"), info)
		if len(crit) > 0 {
			line(bold.Render("What to do now"))
			for _, s := range []string{
				"1. Do not wipe the server yet: take a snapshot at your provider, so there is evidence.",
				"2. From another computer, change every password and key this server held: database, cloud, payment, email.",
				"3. Build a fresh server from your code and backups, rather than cleaning this one.",
				"4. The full guide: https://docs.kiyesi.dev/guides/break-in/",
			} {
				for _, l := range wrap(s, fixWidth+3, 3) {
					line(" " + l)
				}
			}
			line("")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// breachSummary is the answer in one line, the most serious kind first,
// with every other kind counted after it.
func breachSummary(crit, warn, info int) string {
	switch {
	case crit > 0:
		s := redB.Render(plural(crit, "sign", "signs") + " of a break-in")
		if rest := warn + info; rest > 0 {
			s += grey.Render(", and " + plural(rest, "thing", "things") + " to look at")
		}
		return s
	case warn > 0:
		s := amberB.Render(plural(warn, "thing", "things") + " to look at")
		if info > 0 {
			s += grey.Render(", and " + plural(info, "change", "changes") + " to confirm")
		}
		return s
	case info == 1:
		return bold.Render("1 change to confirm: was it your team?")
	default:
		return bold.Render(fmt.Sprintf("%d changes to confirm: were they your team?", info))
	}
}

// breachLifeLine says whether the system still gets security fixes: red
// once they have stopped, amber when they stop soon, grey otherwise, and
// nothing when the dates do not know the system.
func breachLifeLine(life []scan.CheckResult) string {
	if len(life) == 0 {
		return ""
	}
	c := life[0]
	switch {
	case c.Status == "pass":
		return grey.Render(c.Summary)
	case c.Status != "fail" || len(c.Findings) == 0:
		return ""
	}
	f := c.Findings[0]
	switch f.Severity {
	case "critical":
		return red.Render(f.Sentence) + "\n" + grey.Render("How to move to a release that still gets them: sudo kiyesi scan")
	case "warning":
		return amber.Render(f.Sentence)
	default:
		return grey.Render(f.Sentence)
	}
}

// breachHostLine is the server, its system, and how many kinds of sign were
// looked for in how long.
func breachHostLine(r scan.Report, signs int) string {
	os := r.Host.OS
	if !r.Host.Tested {
		os += " (untested)"
	}
	took := fmt.Sprintf("%.1f s", r.Seconds)
	if r.Seconds >= 10 {
		took = fmt.Sprintf("%.0f s", r.Seconds)
	}
	what := plural(signs, "sign", "signs") + " checked"
	if signs <= 0 {
		what = "checked"
	}
	return fmt.Sprintf("%s · %s · %s in %s", r.Host.Name, os, what, took)
}
