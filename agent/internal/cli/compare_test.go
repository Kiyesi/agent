package cli

import (
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

func TestCompareListsWhatDiffers(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "compare", "checkout-api-prod", "new-box")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"checkout-api-prod and new-box differ in 3 things.",
		"SECURITY (3 the same)", "SSH password login", "off", "on",
		"PACKAGES (412 the same)", "openssl", "3.0.13-0ubuntu3.1", "redis-server", "—",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SYSTEM") {
		t.Errorf("a section with nothing different is listed:\n%s", out)
	}
	if code, _, errOut := runCLI(t, "compare", "checkout-api-prod", "nope"); code != ExitUsage || !strings.Contains(errOut, `no server called "nope"`) {
		t.Errorf("unknown server: %d %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, "compare", "checkout-api-prod", "checkout-api-prod"); code != ExitUsage || !strings.Contains(errOut, "two different servers") {
		t.Errorf("same server: %d %s", code, errOut)
	}
	if code, out, _ := runCLI(t, "compare", "checkout-api-prod", "new-box", "--json"); code != ExitOK || !strings.Contains(out, `"differences": 3`) {
		t.Errorf("json: %d %s", code, out)
	}
}

// With one server not read yet, nothing is called a difference.
func TestCompareWithOneServerNotReadYet(t *testing.T) {
	v := "3.0.13-0ubuntu3.4"
	var b strings.Builder
	printComparison(IO{Out: &b, Environ: []string{"NO_COLOR=1"}}, api.Comparison{
		A: api.CompareSide{Name: "web-1", Read: true, Covered: true}, B: api.CompareSide{Name: "web-2", Covered: true},
		Differences: 1, Sections: []api.CompareSection{{Key: "packages", Rows: []api.CompareRow{{Name: "openssl", A: &v}}}},
	})
	out := b.String()
	if !strings.Contains(out, "Only web-1 has been read so far") || strings.Contains(out, "differ in") || !strings.Contains(out, "web-2: its agent has not sent") {
		t.Fatalf("out:\n%s", out)
	}
	b.Reset()
	printComparison(IO{Out: &b, Environ: []string{"NO_COLOR=1"}}, api.Comparison{A: api.CompareSide{Name: "web-1", Covered: true}, B: api.CompareSide{Name: "web-2", Covered: true}})
	if !strings.Contains(b.String(), "Neither server has been read yet") {
		t.Fatalf("out:\n%s", b.String())
	}
}

// A long list is cut by the service; what it left out is counted, never
// silently dropped.
func TestCompareSaysHowManyRowsWereLeftOut(t *testing.T) {
	v := "1"
	var b strings.Builder
	printComparison(IO{Out: &b, Environ: []string{"NO_COLOR=1"}}, api.Comparison{
		A: api.CompareSide{Name: "web-1", Read: true, Covered: true}, B: api.CompareSide{Name: "web-2", Read: true, Covered: true},
		Differences: 214, Sections: []api.CompareSection{{Key: "packages", Rows: []api.CompareRow{{Name: "adduser", A: &v}}, Same: 3, More: 213}},
	})
	if !strings.Contains(b.String(), "… and 213 more that differ") {
		t.Fatalf("out:\n%s", b.String())
	}
}
