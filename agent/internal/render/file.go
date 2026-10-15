package render

import (
	"fmt"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// File writes the full report, with no colour: every finding with why it
// matters and its fix, then what passed, what was skipped and what this
// version does not check yet.
func File(r scan.Report) string {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line(fmt.Sprintf("Kiyesi %s · read-only scan · full report", version.Short()))
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
			for _, l := range wrap("Fix: "+f.Fix, fixWidth, 5) {
				line("       " + l)
			}
			if f.AutoFix != "" {
				line("       Or let Kiyesi do it: sudo kiyesi fix " + f.AutoFix)
			}
			line("")
		}
	}
	section("CRITICAL", "FAIL", crit)
	section("WARNING", "WARN", warn)
	if rows := locations(r); len(rows) > 0 {
		line("DATA LOCATION (home country: " + r.Home.Name + ")")
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
	line("Kiyesi only read this server. It changed nothing and sent nothing.")
	return b.String()
}
