package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// BreakIn prints kiyesi breach-check's answer: no signs, or each sign with
// what it means and what to do, most serious first, and what to do now
// when anything points to a break-in.
func BreakIn(w io.Writer, r scan.Report) error {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line("")
	line(grey.Render(fmt.Sprintf("Kiyesi %s · break-in check · nothing leaves this server", version.Short())))
	line(grey.Render(hostLine(r)))
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
		var crit, warn, info []scan.Finding
		for _, f := range c.Findings {
			switch f.Severity {
			case "critical":
				crit = append(crit, f)
			case "warning":
				warn = append(warn, f)
			default:
				info = append(info, f)
			}
		}
		switch {
		case len(crit) > 0:
			line(redB.Render(plural(len(crit), "sign", "signs") + " of a break-in"))
		case len(warn) > 0:
			line(amberB.Render(plural(len(warn)+len(info), "thing", "things") + " to look at"))
		default:
			line(bold.Render(plural(len(info), "change", "changes") + " to check was your team"))
		}
		line("")
		each := func(mark string, fs []scan.Finding) {
			for _, f := range fs {
				line(" " + mark + "  " + f.Sentence)
				for _, l := range wrap(f.Why, fixWidth, 0) {
					line("       " + grey.Render(l))
				}
				for _, l := range wrap("Fix: "+f.Fix, fixWidth, 5) {
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
