package render

import (
	"fmt"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// By is who wrote a saved report, for its last line.
type By int

const (
	// ByScan is a person's kiyesi scan: it changed and sent nothing.
	ByScan By = iota
	// ByAgent is the agent's service, which sends its results.
	ByAgent
	// ByFix is the check after kiyesi fix changed the server.
	ByFix
	// ByUndo is the check after kiyesi fix undo put a change back.
	ByUndo
	// ByGuard is the check before or after kiyesi guard ran a command.
	ByGuard
)

// footer is the report's last line: what Kiyesi did to make it.
func (b By) footer() string {
	switch b {
	case ByAgent:
		return "The Kiyesi agent wrote this report. It only read this server, and sent the results to the Kiyesi service."
	case ByFix:
		return "Written after kiyesi fix changed this server: sudo kiyesi fix undo lists the changes. The check itself only read it."
	case ByUndo:
		return "Written after kiyesi fix undo put a change back. The check itself only read this server."
	case ByGuard:
		return "Written by kiyesi guard, around a command you ran: sudo kiyesi guard list shows them. The check itself only read this server."
	}
	return "Kiyesi only read this server. It changed nothing and sent nothing."
}

// File writes the full report, with no colour: every finding with why it
// matters and its fix, then the optional clean-ups, what passed, what was
// skipped and what this version does not check yet. by says who wrote it.
func File(r scan.Report, by By) string {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line(fmt.Sprintf("Kiyesi %s · read-only scan · full report", version.Version))
	line(hostLine(r))
	as := "as root"
	if !r.Host.Root {
		as = "without root"
	}
	line("Scanned on " + r.StartedAt.Format("Mon 2 Jan 2006 at 15:04 MST") + ", " + as)
	line("")
	line(fmt.Sprintf("GRADE  %s  %d/100     %s", r.Grade.Letter, r.Grade.Score, summary(r)))
	if r.Grade.BasedOn < r.Grade.Total {
		line(strings.Repeat(" ", 10) + fmt.Sprintf("based on %d of %d checks", r.Grade.BasedOn, r.Grade.Total))
	}
	line("")
	crit, warn := split(r)
	section := func(title, label string, fs []scan.Finding) {
		if len(fs) == 0 {
			return
		}
		line(title)
		for _, f := range fs {
			s := f.Sentence
			if f.Confidence != "" {
				s += " · " + f.Confidence
			}
			line(" " + label + "  " + s)
			for _, l := range wrap("Why: "+f.Why, fixWidth, 5) {
				line("       " + l)
			}
			for _, l := range fixLines(f, fixWidth) {
				line("       " + l)
			}
			line("")
		}
	}
	section("CRITICAL", "FAIL", crit)
	section("WARNING", "WARN", warn)
	// What does not move the grade: clean-ups, so kiyesi fix never offers
	// one the report did not name, and changes to confirm or plan for.
	section("INFO (does not affect the grade)", "INFO", optional(r))
	if rows := locations(r); len(rows) > 0 {
		if r.Home.Code == "" {
			line("DATA LOCATION (no home country chosen: set home_country in /etc/kiyesi/config.yaml, or choose it in the dashboard)")
		} else {
			line("DATA LOCATION (home country: " + r.Home.Name + ")")
		}
		w := nameWidth(rows)
		for _, l := range rows {
			s := locationLine(l, r.Home, w, false)
			if l.Place != "" && !strings.Contains(l.Name, l.Place) {
				s += " (" + l.Place + ")"
			}
			line(s)
		}
		if r.Home.Rule != "" {
			for _, l := range wrap("Rule: "+r.Home.Rule, fixWidth+7, 6) {
				line(" " + l)
			}
		}
		line("")
	}
	var passed, skipped []scan.CheckResult
	for _, c := range r.Checks {
		switch {
		case c.Status == "pass":
			passed = append(passed, c)
		case c.Status == "fail" && onlyInfo(c):
			// It counts as passed in the grade line, so it is listed here.
			c.Summary = "passed, with an optional clean-up above"
			if len(c.Findings) > 1 {
				c.Summary = fmt.Sprintf("passed, with %d optional clean-ups above", len(c.Findings))
			}
			passed = append(passed, c)
		case c.Status == "skip":
			skipped = append(skipped, c)
		}
	}
	if len(passed) > 0 {
		line("PASSED")
		for _, c := range passed {
			line(" PASS  " + c.Name + ": " + c.Summary)
		}
		line("")
	}
	if len(skipped) > 0 {
		line("SKIPPED (never counted as passed)")
		for _, c := range skipped {
			line(" SKIP  " + c.Name + ": " + c.SkipReason)
		}
		line("")
	}
	line(by.footer())
	return b.String()
}

// optional is the info findings: clean-ups that do not move the grade.
func optional(r scan.Report) []scan.Finding {
	var out []scan.Finding
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.Severity == "info" {
				out = append(out, f)
			}
		}
	}
	return out
}

// onlyInfo is a check whose findings are all optional: it still passes.
func onlyInfo(c scan.CheckResult) bool {
	if len(c.Findings) == 0 {
		return false
	}
	for _, f := range c.Findings {
		if f.Severity != "info" {
			return false
		}
	}
	return true
}
