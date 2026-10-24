package render

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/charmbracelet/colorprofile"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
)

func breachOut(tb testing.TB, c scan.CheckResult, seconds float64, d BreakInDetail) string {
	tb.Helper()
	r := scan.Report{Host: scan.Host{Name: "web-1", OS: "Ubuntu 25.04", Tested: false}, Seconds: seconds, Checks: []scan.CheckResult{c}}
	var buf bytes.Buffer
	if err := BreakIn(&colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY}, r, d); err != nil {
		tb.Fatal(err)
	}
	return buf.String()
}

var keyNote = scan.Finding{Check: "break-in", Severity: "info",
	Sentence: "root's login keys changed on 23 Oct 2026",
	Why:      "Each line in that file opens the server to whoever holds the key. Check the change was someone on your team.",
	Fix:      "sudo kiyesi keys lists each key's fingerprint and comment. On your own computer, ssh-keygen -lf ~/.ssh/id_ed25519.pub prints yours to compare. Take out a key nobody recognises with sudo kiyesi keys remove <fingerprint>: it asks first, can be undone, and never takes your own last key"}

// The server's own: Ubuntu 25.04, past its end of life, said under the header.
var lifeEnded = []scan.CheckResult{{ID: "end-of-life", Status: "fail", Findings: []scan.Finding{
	{Check: "end-of-life", Severity: "critical", Sentence: "Ubuntu 25.04 stopped getting security fixes on 15 Jan 2026"},
}}}

func TestBreachCheckClean(t *testing.T) {
	golden(t, "breach-clean.txt", breachOut(t, scan.CheckResult{ID: "break-in", Status: "pass"}, 50.7, BreakInDetail{Signs: 11, Life: lifeEnded}))
}

func TestBreachLifeLine(t *testing.T) {
	for _, c := range []struct {
		life []scan.CheckResult
		want string
	}{
		{lifeEnded, "Ubuntu 25.04 stopped getting security fixes on 15 Jan 2026\nHow to move to a release that still gets them: sudo kiyesi scan"},
		{[]scan.CheckResult{{Status: "pass", Summary: "Ubuntu 24.04.3 LTS gets security fixes until 31 May 2029"}}, "Ubuntu 24.04.3 LTS gets security fixes until 31 May 2029"},
		{[]scan.CheckResult{{Status: "fail", Findings: []scan.Finding{{Severity: "info", Sentence: "Debian GNU/Linux 12 (bookworm) is in long-term support: security fixes until 30 Jun 2028, for most packages"}}}}, "Debian GNU/Linux 12 (bookworm) is in long-term support: security fixes until 30 Jun 2028, for most packages"},
		{[]scan.CheckResult{{Status: "skip", SkipReason: "Kiyesi has no end-of-life dates for Gentoo"}}, ""},
		{nil, ""},
	} {
		// The words; the colours are left out.
		if got := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(breachLifeLine(c.life), ""); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

// One note, with the sign-ins around the change: the summary is a question,
// and the time is whole seconds past ten.
func TestBreachCheckOneNoteWithSignins(t *testing.T) {
	got := breachOut(t, scan.CheckResult{ID: "break-in", Status: "fail", Findings: []scan.Finding{keyNote}}, 50.7, BreakInDetail{
		Signs: 11,
		Below: map[int][]string{0: {
			"SSH sign-ins within a day of the change (23 Oct 14:02 UTC):",
			"  23 Oct 13:58  root from 203.0.113.9, key SHA256:FTTdNdFL… (ada@laptop)",
		}},
	})
	golden(t, "breach-note.txt", got)
}

func TestBreachCheckTwoNotes(t *testing.T) {
	account := scan.Finding{Check: "break-in", Severity: "info", Sentence: "Login account support was added, first seen 22 Oct 2026",
		Why: "Check it was someone on your team.", Fix: "sudo lastlog -u support"}
	golden(t, "breach-notes.txt", breachOut(t, scan.CheckResult{ID: "break-in", Status: "fail", Findings: []scan.Finding{keyNote, account}}, 4.25, BreakInDetail{Signs: 11}))
}

// A sign comes first, and what else was found is counted after it.
func TestBreachCheckSignsAndTheRest(t *testing.T) {
	got := breachOut(t, scan.CheckResult{ID: "break-in", Status: "fail", Findings: []scan.Finding{
		{Check: "break-in", Severity: "critical", Sentence: "A crypto miner is running: xmrig (pid 4242)", Why: "Miners earn attackers money.", Fix: "sudo kill 4242"},
		{Check: "break-in", Severity: "warning", Sentence: "root's shell history is sent to /dev/null", Why: "Attackers turn history off.", Fix: "sudo rm ~root/.bash_history"},
		keyNote,
	}}, 1, BreakInDetail{Signs: 11, Life: lifeEnded})
	golden(t, "breach-signs.txt", got)
}

func TestBreachCheckSkipped(t *testing.T) {
	golden(t, "breach-skip.txt", breachOut(t, scan.CheckResult{ID: "break-in", Status: "skip", SkipReason: "needs root: run sudo kiyesi scan"}, 0.1, BreakInDetail{Signs: 11}))
}

func TestBreachSummaryCounts(t *testing.T) {
	for _, c := range []struct {
		crit, warn, info int
		want             string
	}{
		{0, 0, 1, "1 change to confirm: was it your team?"},
		{0, 0, 2, "2 changes to confirm: were they your team?"},
		{0, 1, 0, "1 thing to look at"},
		{0, 2, 1, "2 things to look at, and 1 change to confirm"},
		{1, 0, 0, "1 sign of a break-in"},
		{2, 1, 1, "2 signs of a break-in, and 2 things to look at"},
	} {
		var buf bytes.Buffer
		w := &colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY}
		_, _ = w.Write([]byte(breachSummary(c.crit, c.warn, c.info)))
		if buf.String() != c.want {
			t.Errorf("%d/%d/%d: %q, want %q", c.crit, c.warn, c.info, buf.String(), c.want)
		}
	}
}
