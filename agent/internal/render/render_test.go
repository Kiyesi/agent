package render

import (
	"bytes"
	"flag"
	"github.com/kiyesi/kiyesi/agent/internal/version"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/colorprofile"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// The design shows version 0.1 in the header; the reports are compared with
// the design, so they are drawn as that version whatever the real one is.
func TestMain(m *testing.M) {
	version.Version, version.Commit = "0.1.0", ""
	// A quarter of an hour after the design report's scan.
	now = func() time.Time { return time.Date(2026, 10, 8, 11, 0, 0, 0, time.UTC) }
	os.Exit(m.Run())
}

// finding resolves a finding from the real pack, as the scan does.
func finding(tb testing.TB, check, key, variant string, vars map[string]string) scan.Finding {
	tb.Helper()
	p, err := packs.English()
	if err != nil {
		tb.Fatal(err)
	}
	ft := p.Check(check).Findings[key]
	fix, auto := ft.Fix, ft.Auto
	if variant != "" {
		fix, auto = ft.FixVariants[variant], ""
	}
	return scan.Finding{
		Check: check, Severity: ft.Severity, Confidence: ft.Confidence,
		Sentence: packs.Fill(ft.Sentence, vars),
		Why:      strings.TrimSpace(packs.Fill(ft.Why, vars)),
		Fix:      strings.TrimSpace(packs.Fill(fix, vars)),
		AutoFix:  auto,
	}
}

// designReport is the example on page 25 of the Stage 1 UI design, without
// the data-location section: 2 critical, 3 warnings, grade D 55.
func designReport(tb testing.TB) scan.Report {
	checks := []scan.CheckResult{
		{ID: "exposed-databases", Name: "Exposed databases", Status: "fail", Findings: []scan.Finding{
			finding(tb, "exposed-databases", "open", "", map[string]string{"database": "Redis", "port": "6379", "service": "redis"})}},
		{ID: "oom", Name: "Out-of-memory kills", Status: "fail", Findings: []scan.Finding{
			finding(tb, "oom", "killed-no-swap", "", map[string]string{"process": "node", "time": "10:41", "total": "1 GB"})}},
		{ID: "certificates", Name: "SSL certificates", Status: "fail", Findings: []scan.Finding{
			finding(tb, "certificates", "expiring", "", map[string]string{"host": "api.example.com", "days": "9"})}},
		{ID: "ssh", Name: "SSH settings", Status: "fail", Findings: []scan.Finding{finding(tb, "ssh", "password", "", nil)}},
		{ID: "backups", Name: "Backups", Status: "fail", Findings: []scan.Finding{
			finding(tb, "backups", "old", "", map[string]string{"age": "31 hours", "limit": "24", "when": "Wed 7 Oct at 04:00"})}},
	}
	checks = append(checks,
		scan.CheckResult{ID: "server-location", Name: "Server location", Status: "fail", Locations: []scan.Location{
			{Check: "server-location", Kind: "Server", Name: "DigitalOcean, London, UK", Place: "London, UK", Country: "GB", Confidence: "confirmed"}}},
		scan.CheckResult{ID: "database-connections", Name: "Database connections", Status: "fail", Locations: []scan.Location{
			{Check: "database-connections", Kind: "Database", Name: "redis (this server)", Place: "London, UK", Country: "GB", Confidence: "confirmed"},
			{Check: "database-connections", Kind: "Database", Name: "checkout-db-prod:5432", Place: "London, UK", Country: "GB", Confidence: "likely"}}},
	)
	for range 15 {
		checks = append(checks, scan.CheckResult{ID: "x", Name: "Load", Status: "pass", Summary: "15-minute load is 0.20 per CPU core"})
	}
	return scan.Report{
		Schema: scan.Schema, Version: "0.1.0",
		Host:       scan.Host{Name: "checkout-api-prod", OS: "Ubuntu 22.04", Tested: true, Root: true},
		StartedAt:  time.Date(2026, 10, 8, 10, 45, 0, 0, time.UTC),
		Seconds:    6.4,
		Grade:      scan.Grade{Score: 55, Letter: "D", BasedOn: 22, Total: 22},
		Counts:     scan.Counts{Critical: 2, Warnings: 3, Passed: 17, Run: 22},
		Checks:     checks,
		Home:       scan.Home{Code: "NG", Name: "Nigeria", Rule: "On 15 June 2026 the Central Bank of Nigeria directed that payment transaction data created in Nigeria be stored and managed in Nigeria by 1 January 2027."},
		ReportFile: "/var/lib/kiyesi/report-2026-10-08.txt",
	}
}

func terminal(tb testing.TB, r scan.Report, profile colorprofile.Profile) string {
	tb.Helper()
	var buf bytes.Buffer
	w := &colorprofile.Writer{Forward: &buf, Profile: profile}
	if err := Terminal(w, r, nil, false); err != nil {
		tb.Fatal(err)
	}
	return buf.String()
}

func golden(tb testing.TB, name, got string) {
	tb.Helper()
	path := "testdata/" + name
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("%v (run go test ./internal/render -update to create it)", err)
	}
	if string(want) != got {
		tb.Errorf("%s differs from the golden file; if the change is intended, run go test ./internal/render -update and review the diff.\n--- got ---\n%s", name, got)
	}
}

// The plain report must match the design line for line, apart from the
// swap fix's extra fstab line (so swap survives a reboot) and the footer
// line for kiyesi connect, which arrives in week 2.
func TestTerminalMatchesTheDesign(t *testing.T) {
	got := terminal(t, designReport(t), colorprofile.NoTTY)
	design := []string{
		"Kiyesi 0.1 · read-only scan · nothing leaves this server",
		"checkout-api-prod · Ubuntu 22.04 · 22 checks in 6.4 s",
		"GRADE  D  55/100     2 critical · 3 warnings · 17 passed",
		"CRITICAL",
		" FAIL  Redis is open to the internet on port 6379 · likely",
		"       Fix: bind the port to 127.0.0.1 in docker-compose.yml, then",
		"            docker compose up -d redis",
		" FAIL  The node process was killed for using too much memory at 10:41",
		"       Fix: sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile &&",
		"            sudo mkswap /swapfile && sudo swapon /swapfile &&",
		"            echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab",
		"WARNING",
		" WARN  SSL certificate for api.example.com expires in 9 days",
		" WARN  SSH allows password login",
		" WARN  Newest backup is 31 hours old",
		"DATA LOCATION",
		" Server     DigitalOcean, London, UK     confirmed   outside Nigeria",
		" Database   redis (this server)          confirmed   outside Nigeria",
		" Database   checkout-db-prod:5432        likely      outside Nigeria",
		"Full report with every fix command: /var/lib/kiyesi/report-2026-10-08.txt",
	}
	lines := strings.Split(got, "\n")
	at := 0
	for _, want := range design {
		for at < len(lines) && lines[at] != want {
			at++
		}
		if at == len(lines) {
			t.Fatalf("line %q is missing or out of order in:\n%s", want, got)
		}
	}
	for _, l := range lines {
		if len([]rune(l)) > 80 {
			t.Errorf("line wider than 80 columns: %q", l)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Error("colour codes in output that is not a terminal")
	}
	if strings.Contains(got, "Why:") || strings.Contains(got, "sudo certbot renew") {
		t.Error("warnings must keep their fix and why for the saved report")
	}
	golden(t, "terminal.txt", got)
}

func TestWrapNeverSplitsQuotes(t *testing.T) {
	got := wrap("Fix: echo \"PasswordAuthentication no\" | sudo tee /etc/ssh/sshd_config.d/00-kiyesi-no-password.conf && sudo systemctl reload ssh", fixWidth, 5)
	for _, l := range got {
		if strings.Count(l, `"`)%2 != 0 {
			t.Errorf("quote split across lines: %q", got)
		}
	}
}

func TestTerminalColours(t *testing.T) {
	got := terminal(t, designReport(t), colorprofile.TrueColor)
	for _, want := range []string{
		"\x1b[1;38;2;255;255;255;48;2;181;71;27m D \x1b[m", // white D on #B5471B
		"\x1b[31mFAIL\x1b[m", // red
		"\x1b[33mWARN\x1b[m", // amber
		"\x1b[90mKiyesi 0.1", // grey header
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in coloured output", want)
		}
	}
	golden(t, "terminal-colour.txt", got)
}

func TestTerminalSaysWhatTheGradeIsBasedOn(t *testing.T) {
	r := designReport(t)
	r.Counts = scan.Counts{Critical: 2, Warnings: 3, Passed: 10, Skipped: 2, Run: 15}
	r.Grade.BasedOn = 15
	r.Checks = append(r.Checks, scan.CheckResult{Name: "Firewall", Status: "skip", SkipReason: "needs root: run sudo kiyesi scan"})
	got := terminal(t, r, colorprofile.NoTTY)
	for _, want := range []string{
		"GRADE  D  55/100     2 critical · 3 warnings · 10 passed · 2 skipped",
		"          based on 15 of 22 checks",
		" SKIP  Firewall: needs root: run sudo kiyesi scan",
		"checkout-api-prod · Ubuntu 22.04 · 17 checks in 6.4 s",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// The docs site shows this file as its example report, so the example is
// always the renderer's real output.
func TestExampleForTheDocs(t *testing.T) {
	r := designReport(t)
	// The docs and website show this to everyone, so its home country is the
	// demo's, not one Kiyesi might seem to be made for.
	r.Home = scan.Home{Code: "DE", Name: "Germany"}
	golden(t, "terminal-example.txt", terminal(t, r, colorprofile.NoTTY))
}

// Two of the design's findings (the certificate and SSH passwords) are
// ones kiyesi fix can make, so the report says so, and the saved report
// names the fix under each.
func TestReportsOfferKiyesiFix(t *testing.T) {
	r := designReport(t)
	if got := terminal(t, r, colorprofile.NoTTY); !strings.Contains(got, "Kiyesi can fix 2 things for you: sudo kiyesi fix\nIt says what it will change, and asks first.\n") {
		t.Errorf("no kiyesi fix line in:\n%s", got)
	}
	file := File(r, ByScan)
	for _, want := range []string{"Or let Kiyesi do it: sudo kiyesi fix ssh-password", "Or let Kiyesi do it: sudo kiyesi fix certificates"} {
		if !strings.Contains(file, want) {
			t.Errorf("missing %q in the saved report", want)
		}
	}
	if strings.Count(file, "Or let Kiyesi do it") != 2 {
		t.Errorf("a finding kiyesi fix cannot make was offered:\n%s", file)
	}
	var b bytes.Buffer
	if err := Stored(&colorprofile.Writer{Forward: &b, Profile: colorprofile.NoTTY}, r, "checkout-api-prod"); err != nil || !strings.Contains(b.String(), "Kiyesi can fix 2 things on the server: sudo kiyesi fix") {
		t.Errorf("laptop view: %v\n%s", err, b.String())
	}
	// None to offer, no line.
	for i := range r.Checks {
		for j := range r.Checks[i].Findings {
			r.Checks[i].Findings[j].AutoFix = ""
		}
	}
	if got := terminal(t, r, colorprofile.NoTTY); strings.Contains(got, "kiyesi fix") {
		t.Errorf("offered kiyesi fix with nothing to fix:\n%s", got)
	}
}

func TestTerminalMarksAnUntestedSystem(t *testing.T) {
	r := designReport(t)
	r.Host.OS, r.Host.Tested = "Debian 12", false
	if got := terminal(t, r, colorprofile.NoTTY); !strings.Contains(got, "checkout-api-prod · Debian 12 (untested) · ") {
		t.Errorf("untested system not marked:\n%s", got)
	}
}

func TestReportFileHasEveryFix(t *testing.T) {
	got := File(designReport(t), ByScan)
	for _, want := range []string{"sudo certbot renew", "Why: When it expires", "PASSED", "DATA LOCATION (home country: Nigeria)", "Rule: On 15 June 2026", "It changed nothing and sent nothing."} {
		if !strings.Contains(got, want) {
			t.Errorf("report file is missing %q", want)
		}
	}
	golden(t, "report-file.txt", got)
}

func TestJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, designReport(t)); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.json", buf.String())
}

func TestDataLocationColumnsStayInLine(t *testing.T) {
	r := designReport(t)
	r.Checks[5].Locations[0].Name = "DigitalOcean, Frankfurt, Germany"
	got := terminal(t, r, colorprofile.NoTTY)
	var cols []int
	for _, l := range strings.Split(got, "\n") {
		if i := strings.Index(l, "confirmed"); i > 0 && strings.HasPrefix(l, " Server") || strings.HasPrefix(l, " Database") {
			cols = append(cols, strings.Index(l, "outside"))
		}
	}
	if len(cols) != 3 || cols[0] != cols[1] || cols[1] != cols[2] {
		t.Errorf("verdict columns %v are not in line:\n%s", cols, got)
	}
}

// The report is readable by root only, so after sudo the footer says how to open it.
func TestFooterSaysHowToOpenARootOnlyReport(t *testing.T) {
	var buf bytes.Buffer
	w := &colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY}
	if err := Terminal(w, designReport(t), nil, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Full report with every fix command: sudo less /var/lib/kiyesi/report-2026-10-08.txt") {
		t.Errorf("footer:\n%s", buf.String())
	}
}

// At A 100 the only thing kiyesi fix could do is an optional clean-up: the
// report does not offer it, so a perfect grade never reads as a problem.
func TestAPerfectGradeOffersNoFix(t *testing.T) {
	r := designReport(t)
	r.Grade, r.Counts = scan.Grade{Score: 100, Letter: "A", BasedOn: 23, Total: 23}, scan.Counts{Passed: 23, Run: 23}
	r.Checks = []scan.CheckResult{{ID: "leftovers", Name: "Leftovers", Status: "pass", Findings: []scan.Finding{
		{Check: "leftovers", Severity: "info", AutoFix: "docker-cleanup", Sentence: "Docker keeps 2.4 GB that nothing uses: old images and build cache"},
	}}}
	if got := terminal(t, r, colorprofile.NoTTY); strings.Contains(got, "kiyesi fix") {
		t.Errorf("offered kiyesi fix at A 100:\n%s", got)
	}
	var b bytes.Buffer
	if err := Stored(&colorprofile.Writer{Forward: &b, Profile: colorprofile.NoTTY}, r, "kiyesi-server"); err != nil || strings.Contains(b.String(), "kiyesi fix") {
		t.Errorf("laptop view offered kiyesi fix at A 100: %v\n%s", err, b.String())
	}
}

// The saved report names every optional clean-up kiyesi fix may offer,
// lists its check under PASSED as the grade line counts it, and never
// mixes it with what affects the grade.
func TestReportFileNamesOptionalCleanUps(t *testing.T) {
	r := designReport(t)
	r.Counts.Passed++
	r.Checks = append(r.Checks, scan.CheckResult{ID: "leftovers", Name: "Leftovers", Status: "fail", Findings: []scan.Finding{
		finding(t, "leftovers", "docker-waste", "", map[string]string{"size": "2.4 GB"}),
	}})
	got := File(r, ByScan)
	at := strings.Index(got, "OPTIONAL (does not affect the grade)\n INFO  Docker keeps 2.4 GB that nothing uses")
	if at < 0 || at < strings.Index(got, "WARNING") || at > strings.Index(got, "DATA LOCATION") {
		t.Fatalf("no OPTIONAL section between WARNING and DATA LOCATION:\n%s", got)
	}
	if !strings.Contains(got[at:], "Or let Kiyesi do it: sudo kiyesi fix docker-cleanup") || !strings.Contains(got[at:], "Why: ") {
		t.Errorf("the clean-up has no why or kiyesi fix line:\n%s", got[at:])
	}
	if !strings.Contains(got, " PASS  Leftovers: passed, with an optional clean-up above\n") {
		t.Errorf("Leftovers is counted as passed but not listed:\n%s", got)
	}
	if n := strings.Count(got, " PASS  "); n != r.Counts.Passed-2 {
		// The design's 17 passed include 2 checks only shown as locations.
		t.Errorf("listed %d passed, counted %d", n, r.Counts.Passed)
	}
}

// The last line says who wrote the report and what it did.
func TestReportFileSaysWhoWroteIt(t *testing.T) {
	for by, want := range map[By]string{
		ByScan:  "Kiyesi only read this server. It changed nothing and sent nothing.\n",
		ByAgent: "The Kiyesi agent wrote this report. It only read this server, and sent the results to the Kiyesi service.\n",
		ByFix:   "Written after kiyesi fix changed this server: sudo kiyesi fix undo lists the changes. The check itself only read it.\n",
		ByUndo:  "Written after kiyesi fix undo put a change back. The check itself only read this server.\n",
	} {
		got := File(designReport(t), by)
		if !strings.HasSuffix(got, want) {
			t.Errorf("by %d ends:\n%s", by, got[strings.LastIndex(strings.TrimSuffix(got, "\n"), "\n")+1:])
		}
		if by != ByScan && strings.Contains(got, "sent nothing") {
			t.Errorf("by %d says it sent nothing", by)
		}
	}
}

// One fix for three secret files is one thing to fix, as kiyesi fix says.
func TestReportsCountFixesNotFindings(t *testing.T) {
	r := designReport(t)
	var secrets []scan.Finding
	for _, p := range []string{"/srv/a/.env", "/srv/b/.env", "/srv/c/.env"} {
		secrets = append(secrets, finding(t, "secrets-in-files", "world-readable", "", map[string]string{"path": p}))
	}
	r.Checks = []scan.CheckResult{{ID: "secrets-in-files", Name: "Secrets", Status: "fail", Findings: secrets}}
	if got := terminal(t, r, colorprofile.NoTTY); !strings.Contains(got, "Kiyesi can fix 1 thing for you: sudo kiyesi fix") {
		t.Errorf("counted findings, not fixes:\n%s", got)
	}
}

// The laptop view shows the agent's version and when it scanned, and a
// scan over a day old offers no fix: it says how old it is instead.
func TestLaptopViewShowsTheAgentsVersionAndTheScanTime(t *testing.T) {
	r := designReport(t)
	r.Version = "0.33.2"
	var b bytes.Buffer
	if err := Stored(&colorprofile.Writer{Forward: &b, Profile: colorprofile.NoTTY}, r, "checkout-api-prod"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Kiyesi 0.33.2 · checkout-api-prod · scanned 15 minutes ago\n") {
		t.Errorf("header:\n%s", b.String())
	}
	old := now
	t.Cleanup(func() { now = old })
	now = func() time.Time { return r.StartedAt.Add(3*24*time.Hour + time.Hour) }
	b.Reset()
	if err := Stored(&colorprofile.Writer{Forward: &b, Profile: colorprofile.NoTTY}, r, "checkout-api-prod"); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if strings.Contains(got, "sudo kiyesi fix") || !strings.Contains(got, "This scan is 3 days old, so it may no longer be true.") || !strings.Contains(got, "scanned 3 days ago") {
		t.Errorf("a 3-day-old scan:\n%s", got)
	}
}
