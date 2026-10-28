package cli

import (
	"os"
	"strings"
	"testing"
)

// No test asks get.kiyesi.dev: the daily update line is replaced for all of them.
func TestMain(m *testing.M) {
	updateNotice = func() string { return "" }
	os.Exit(m.Run())
}

func TestTheUpdateLineFollowsAPersonsCommandButNotScriptsOrTheService(t *testing.T) {
	asTerminal(t, 0)
	old := updateNotice
	t.Cleanup(func() { updateNotice = old })
	asked := 0
	updateNotice = func() string { asked++; return "kiyesi 0.44.0 is out: run sudo kiyesi update" }

	var out, errOut strings.Builder
	if code := Execute([]string{"version"}, IO{Out: &out, Err: &errOut}); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "kiyesi 0.44.0 is out: run sudo kiyesi update") {
		t.Fatalf("no line after a person's command: %q", errOut.String())
	}
	if strings.Contains(out.String(), "is out") {
		t.Fatal("the line went to the output, where scripts read")
	}

	for _, args := range [][]string{{"version", "--json"}, {"update", "--help"}} {
		errOut.Reset()
		before := asked
		Execute(args, IO{Out: &out, Err: &errOut})
		if asked != before {
			t.Errorf("%v asked for the update line", args)
		}
	}
	errOut.Reset()
	before := asked
	Execute([]string{"version"}, IO{Out: &out, Err: &errOut, Environ: []string{"KIYESI_NO_UPDATE_NOTICE=1"}})
	if asked != before {
		t.Error("KIYESI_NO_UPDATE_NOTICE was not respected")
	}
}
