package checks

import (
	"context"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func eolRun(t *testing.T, e *testEnv, os system.OSInfo, at time.Time) Result {
	t.Helper()
	env := e.env()
	env.Sys.OS = os
	env.Sys.Now = func() time.Time { return at }
	return endOfLifeCheck{}.Run(context.Background(), env)
}

var oct24 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

// The user's server: Ubuntu 25.04 stopped getting fixes on 15 January 2026,
// Canonical's own day (endoflife.date says the 17th).
func TestEndOfLifeUbuntuInterimPast(t *testing.T) {
	r := eolRun(t, newTestEnv(), system.OSInfo{ID: "ubuntu", VersionID: "25.04", Name: "Ubuntu 25.04"}, oct24)
	wantStatus(t, r, StatusFail, "ended")
	if f := r.Findings[0]; f.Vars["date"] != "15 Jan 2026" || f.Variant != "ubuntu" || f.Vars["os"] != "Ubuntu 25.04" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestEndOfLifeSupportedReleasePasses(t *testing.T) {
	r := eolRun(t, newTestEnv(), system.OSInfo{ID: "ubuntu", VersionID: "24.04", Name: "Ubuntu 24.04.3 LTS"}, oct24)
	wantStatus(t, r, StatusPass)
	if r.Vars["date"] != "31 May 2029" || r.Vars["with"] != "" {
		t.Fatalf("vars = %v", r.Vars)
	}
}

// Ubuntu 20.04's free fixes ended in 2025; with Ubuntu Pro's esm-infra on,
// its fixes go on to May 2030, and the check passes saying so.
func TestEndOfLifeUbuntuProExtends(t *testing.T) {
	focal := system.OSInfo{ID: "ubuntu", VersionID: "20.04", Name: "Ubuntu 20.04.6 LTS"}
	wantStatus(t, eolRun(t, newTestEnv(), focal, oct24), StatusFail, "ended")
	e := newTestEnv().file("var/lib/ubuntu-advantage/status.json", `{"services":[{"name":"esm-apps","status":"enabled"},{"name":"esm-infra","status":"enabled"}]}`)
	r := eolRun(t, e, focal, oct24)
	wantStatus(t, r, StatusPass)
	if r.Vars["with"] != " with Ubuntu Pro" || r.Vars["date"] != "31 May 2030" {
		t.Fatalf("vars = %v", r.Vars)
	}
	// Pro attached but esm-infra off: the free date counts.
	off := newTestEnv().file("var/lib/ubuntu-advantage/status.json", `{"services":[{"name":"esm-infra","status":"disabled"}]}`)
	wantStatus(t, eolRun(t, off, focal, oct24), StatusFail, "ended")
}

// Within 90 days of the end: a warning with the days left, counted to the
// end of the last day.
func TestEndOfLifeEndingSoon(t *testing.T) {
	bookworm := system.OSInfo{ID: "debian", VersionID: "12", Name: "Debian GNU/Linux 12 (bookworm)"}
	r := eolRun(t, newTestEnv(), bookworm, time.Date(2028, 5, 10, 0, 0, 0, 0, time.UTC))
	wantStatus(t, r, StatusFail, "ending")
	if f := r.Findings[0]; f.Vars["date"] != "30 Jun 2028" || f.Vars["days"] != "51" || f.Variant != "debian" {
		t.Fatalf("finding = %+v", f)
	}
	// On its last day it still gets fixes; the day after, it does not.
	wantStatus(t, eolRun(t, newTestEnv(), bookworm, time.Date(2028, 6, 30, 23, 0, 0, 0, time.UTC)), StatusFail, "ending")
	wantStatus(t, eolRun(t, newTestEnv(), bookworm, time.Date(2028, 7, 1, 0, 0, 0, 0, time.UTC)), StatusFail, "ended")
}

// The warning starts when 90 days are left, by the date, not the hour.
func TestEndOfLifeWarnsFrom90Days(t *testing.T) {
	noble := system.OSInfo{ID: "ubuntu", VersionID: "24.04", Name: "Ubuntu 24.04.3 LTS"}
	r := eolRun(t, newTestEnv(), noble, time.Date(2029, 3, 2, 23, 59, 0, 0, time.UTC))
	wantStatus(t, r, StatusFail, "ending")
	if d := r.Findings[0].Vars["days"]; d != "90" {
		t.Fatalf("days = %s, want 90", d)
	}
	wantStatus(t, eolRun(t, newTestEnv(), noble, time.Date(2029, 3, 1, 23, 59, 0, 0, time.UTC)), StatusPass)
}

// Debian: the security team's own support, then long-term support to the
// last day. During long-term support a note that costs nothing; 90 days
// before its end a warning; after it, critical.
func TestEndOfLifeDebianLongTermSupport(t *testing.T) {
	bookworm := system.OSInfo{ID: "debian", VersionID: "12", Name: "Debian GNU/Linux 12 (bookworm)"}
	// Debian's security team supported 12 until 11 July 2026.
	r := eolRun(t, newTestEnv(), bookworm, time.Date(2026, 7, 11, 23, 0, 0, 0, time.UTC))
	wantStatus(t, r, StatusPass)
	if r.Vars["date"] != "30 Jun 2028" {
		t.Fatalf("vars = %v", r.Vars)
	}
	r = eolRun(t, newTestEnv(), bookworm, oct24)
	wantStatus(t, r, StatusFail, "lts")
	if f := r.Findings[0]; f.Vars["date"] != "30 Jun 2028" || f.Variant != "debian" {
		t.Fatalf("finding = %+v", f)
	}
	// Debian 11's long-term support ended on 31 August 2026.
	bullseye := system.OSInfo{ID: "debian", VersionID: "11", Name: "Debian GNU/Linux 11 (bullseye)"}
	wantStatus(t, eolRun(t, newTestEnv(), bullseye, oct24), StatusFail, "ended")
	// Debian 13 is still with the security team.
	trixie := system.OSInfo{ID: "debian", VersionID: "13", Name: "Debian GNU/Linux 13 (trixie)"}
	wantStatus(t, eolRun(t, newTestEnv(), trixie, oct24), StatusPass)
}

func TestEndOfLifeVersionRules(t *testing.T) {
	for _, c := range []struct {
		os   system.OSInfo
		want Status
		key  string
	}{
		{system.OSInfo{ID: "rocky", VersionID: "9.4", Name: "Rocky Linux 9.4"}, StatusPass, ""},
		{system.OSInfo{ID: "centos", VersionID: "7", Name: "CentOS Linux 7 (Core)"}, StatusFail, "ended"},
		{system.OSInfo{ID: "centos", VersionID: "9", Name: "CentOS Stream 9"}, StatusPass, ""},
		{system.OSInfo{ID: "amzn", VersionID: "2023", Name: "Amazon Linux 2023"}, StatusPass, ""},
		{system.OSInfo{ID: "alpine", VersionID: "3.12.0", Name: "Alpine Linux v3.12"}, StatusFail, "ended"},
	} {
		r := eolRun(t, newTestEnv(), c.os, oct24)
		if r.Status != c.want || (c.key != "" && r.Findings[0].Key != c.key) {
			t.Errorf("%s: %+v", c.os.Name, r)
		}
	}
}

// Never "fine" for what the table does not know.
func TestEndOfLifeUnknownIsSkippedNotPassed(t *testing.T) {
	r := eolRun(t, newTestEnv(), system.OSInfo{ID: "ubuntu", VersionID: "99.04", Name: "Ubuntu 99.04"}, oct24)
	if r.Status != StatusSkip || r.SkipKey != "unknown-release" || r.SkipVars["fetched"] == "" {
		t.Fatalf("unknown release: %+v", r)
	}
	r = eolRun(t, newTestEnv(), system.OSInfo{ID: "gentoo", VersionID: "2.17", Name: "Gentoo"}, oct24)
	if r.Status != StatusSkip || r.SkipKey != "unknown-system" {
		t.Fatalf("unknown system: %+v", r)
	}
}
