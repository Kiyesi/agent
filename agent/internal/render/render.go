// Package render prints a scan: the terminal report, the saved report file
// and JSON. The terminal layout follows page 25 of the Stage 1 UI design.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// fixWidth is where fix lines wrap, after a 7-character indent, so every
// line stays inside an 80-column terminal.
const fixWidth = 70

// gradeColours are the solid blocks behind the grade letter.
var gradeColours = map[string]string{
	"A": "#0F7A47", "B": "#2C7A7B", "C": "#9A5B00", "D": "#B5471B", "F": "#B3261E",
}

var (
	grey   = lipgloss.NewStyle().Foreground(lipgloss.BrightBlack)
	red    = lipgloss.NewStyle().Foreground(lipgloss.Red)
	amber  = lipgloss.NewStyle().Foreground(lipgloss.Yellow)
	bold   = lipgloss.NewStyle().Bold(true)
	redB   = red.Bold(true)
	amberB = amber.Bold(true)
)

// NewWriter wraps w so colours are dropped when w is not a terminal or when
// NO_COLOR is set.
func NewWriter(w io.Writer, environ []string) *colorprofile.Writer {
	return colorprofile.NewWriter(w, environ)
}

// Terminal prints the short report. Critical findings show their fix;
// warnings keep theirs for the saved report. viaSudo says the scan ran
// under sudo: the report is readable by root only, so the footer says how
// to open it.
func Terminal(w io.Writer, r scan.Report, saveErr error, viaSudo bool) error {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }

	line("")
	line(grey.Render(fmt.Sprintf("Kiyesi %s · read-only scan · nothing leaves this server", version.Short())))
	body(&b, r)
	if n := fixable(r); n > 0 {
		line(bold.Render(fmt.Sprintf("Kiyesi can fix %d of these for you:", n)) + " sudo kiyesi fix")
		line(grey.Render("It says what it will change, and asks first."))
		line("")
	}
	if saveErr != nil {
		line(grey.Render("The full report could not be saved: " + saveErr.Error() + ". Run sudo kiyesi scan, or kiyesi scan --json."))
	} else if r.ReportFile != "" {
		path := r.ReportFile
		if viaSudo {
			path = "sudo less " + path
		}
		line(grey.Render("Full report with every fix command: " + path))
	}
	line("")
	_, err := io.WriteString(w, b.String())
	return err
}

// Stored prints a server's latest report as the service keeps it, for
// kiyesi server <name> on a laptop.
func Stored(w io.Writer, r scan.Report, name string) error {
	var b strings.Builder
	b.WriteString("\n" + grey.Render(fmt.Sprintf("Kiyesi %s · %s · latest scan sent by the agent", version.Short(), name)) + "\n")
	body(&b, r)
	if n := fixable(r); n > 0 {
		b.WriteString(bold.Render(fmt.Sprintf("Kiyesi can fix %d of these on the server:", n)) + " sudo kiyesi fix\n\n")
	}
	b.WriteString(grey.Render("Every fix command: kiyesi server "+name+" --json, or the dashboard.") + "\n\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// body is the report itself: host, grade, findings, data location, skipped.
func body(b *strings.Builder, r scan.Report) {
	line := func(s string) { b.WriteString(s + "\n") }
	line(grey.Render(hostLine(r)))
	line("")
	gradeLines(b, r)
	line("")

	crit, warn := split(r)
	if len(crit) > 0 {
		line(redB.Render("CRITICAL"))
		for _, f := range crit {
			line(" " + red.Render("FAIL") + "  " + sentence(f))
			for _, fl := range wrap("Fix: "+f.Fix, fixWidth, 5) {
				line("       " + grey.Render(fl))
			}
		}
		line("")
	}
	if len(warn) > 0 {
		line(amberB.Render("WARNING"))
		for _, f := range warn {
			line(" " + amber.Render("WARN") + "  " + sentence(f))
		}
		line("")
	}
	if rows := locations(r); len(rows) > 0 {
		line(bold.Render("DATA LOCATION"))
		w := nameWidth(rows)
		for _, l := range rows {
			line(locationLine(l, r.Home, w, true))
		}
		line("")
	}
	if skipped := skippedChecks(r); len(skipped) > 0 {
		line(grey.Bold(true).Render("SKIPPED"))
		for _, c := range skipped {
			line(" " + grey.Render("SKIP  "+c.Name+": "+c.SkipReason))
		}
		line("")
	}
}

// fixable counts the findings kiyesi fix can make for you.
func fixable(r scan.Report) int {
	n := 0
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.AutoFix != "" {
				n++
			}
		}
	}
	return n
}

func hostLine(r scan.Report) string {
	os := r.Host.OS
	if !r.Host.Tested {
		os += " (untested)"
	}
	return fmt.Sprintf("%s · %s · %s in %.1f s", r.Host.Name, os, plural(r.Counts.Run+r.Counts.Skipped, "check", "checks"), r.Seconds)
}

// gradeLines prints the grade and the counts. When some checks did not
// run, a second line says what the grade is based on.
func gradeLines(b *strings.Builder, r scan.Report) {
	letter := r.Grade.Letter
	block := lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color(gradeColours[letter])).
		Render(" " + letter + " ")
	b.WriteString(bold.Render("GRADE") + " " + block + " " + bold.Render(fmt.Sprintf("%d/100", r.Grade.Score)) + "     " + summary(r) + "\n")
	if r.Grade.BasedOn < r.Grade.Total {
		b.WriteString(strings.Repeat(" ", 10) + grey.Render(fmt.Sprintf("based on %d of %d checks", r.Grade.BasedOn, r.Grade.Total)) + "\n")
	}
}

func summary(r scan.Report) string {
	c := r.Counts
	parts := []string{
		fmt.Sprintf("%d critical", c.Critical),
		plural(c.Warnings, "warning", "warnings"),
		fmt.Sprintf("%d passed", c.Passed),
	}
	if c.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", c.Skipped))
	}
	return strings.Join(parts, " · ")
}

func sentence(f scan.Finding) string {
	if f.Confidence == "" {
		return f.Sentence
	}
	return f.Sentence + grey.Render(" · "+f.Confidence)
}

func split(r scan.Report) (crit, warn []scan.Finding) {
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			switch f.Severity {
			case "critical":
				crit = append(crit, f)
			case "warning":
				warn = append(warn, f)
			}
		}
	}
	return crit, warn
}

func locations(r scan.Report) []scan.Location {
	var out []scan.Location
	for _, c := range r.Checks {
		out = append(out, c.Locations...)
	}
	return out
}

// locationLine lays out one data-location row in the design's columns:
// kind, what it is, how sure, and inside or outside the home country.
// nameWidth is the design's 28 columns, or wider when a name needs it, so
// the columns stay in line.
func nameWidth(rows []scan.Location) int {
	w := 28
	for _, l := range rows {
		w = max(w, len([]rune(l.Name)))
	}
	return w
}

func locationLine(l scan.Location, h scan.Home, width int, colour bool) string {
	home := h.Name
	conf := l.Confidence
	var verdict string
	switch {
	case l.Review:
		conf, verdict = "", "listed for review"
	case l.Country == "":
		conf, verdict = "unknown", "found once connected"
	default:
		verdict = "in " + home
	}
	outside := !l.Review && l.Country != "" && !strings.EqualFold(l.Country, h.Code)
	if outside {
		verdict = "outside " + home
	}
	if colour {
		switch {
		case outside:
			verdict = amber.Render(verdict)
		case l.Review || l.Country == "":
			verdict = grey.Render(verdict)
		}
	}
	return " " + pad(l.Kind, 10) + " " + pad(l.Name, width) + " " + pad(conf, 11) + " " + verdict
}

func pad(s string, n int) string {
	if w := len([]rune(s)); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

func skippedChecks(r scan.Report) []scan.CheckResult {
	var out []scan.CheckResult
	for _, c := range r.Checks {
		if c.Status == "skip" {
			out = append(out, c)
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// wrap breaks s into lines of at most w characters. Lines after the first
// are indented by indent spaces, and an explicit newline starts a new line,
// as in the design's two-line Compose fix. A break goes after && or | where
// possible, and never inside quotes, so a copied command still works.
func wrap(s string, w, indent int) []string {
	var out []string
	pad := strings.Repeat(" ", indent)
	for i, para := range strings.Split(s, "\n") {
		cur := ""
		if i > 0 {
			cur = pad
		}
		for _, chunk := range chunks(para) {
			switch {
			case strings.TrimSpace(cur) == "":
				cur += chunk
			case len(cur)+1+len(chunk) > w:
				out = append(out, cur)
				cur = pad + chunk
			default:
				cur += " " + chunk
			}
		}
		out = append(out, cur)
	}
	return out
}

// chunks splits a line into the pieces wrap may break between: whole
// commands ending in && or |, or single words when a command is too long.
// Quoted text is never split.
func chunks(s string) []string {
	words := quotedFields(s)
	var cmds [][]string
	var cur []string
	for _, word := range words {
		cur = append(cur, word)
		if word == "&&" || word == "|" || word == "||" {
			cmds = append(cmds, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		cmds = append(cmds, cur)
	}
	var out []string
	for _, c := range cmds {
		joined := strings.Join(c, " ")
		if len(joined) <= fixWidth-5 {
			out = append(out, joined)
		} else {
			out = append(out, c...)
		}
	}
	return out
}

// quotedFields splits at spaces outside single or double quotes.
func quotedFields(s string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
			b.WriteRune(r)
		case r == ' ' || r == '\t':
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// JSON prints the report as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// JSONLine writes v as JSON on one line, for streams such as kiyesi logs --follow --json.
func JSONLine(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}
