package cli

import (
	"slices"
	"strings"
	"testing"
)

// complete asks for completions the way a shell does.
func complete(t *testing.T, args ...string) []string {
	t.Helper()
	_, out, _ := runCLI(t, append([]string{"__complete"}, args...)...)
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" && !strings.HasPrefix(l, ":") && !strings.HasPrefix(l, "Completion ended") {
			got = append(got, strings.SplitN(l, "\t", 2)[0])
		}
	}
	return got
}

func TestCompletionScriptsForEachShell(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		code, out, errOut := runCLI(t, "completion", shell)
		if code != ExitOK || !strings.Contains(out, "kiyesi") || len(out) < 500 {
			t.Errorf("%s: %d %q", shell, code, errOut)
		}
	}
}

func TestCompletionNamesServersIncidentsProjectsAndScreens(t *testing.T) {
	signInForTest(t)
	if got := complete(t, "server", "check"); strings.Join(got, ",") != "checkout-api-prod" {
		t.Errorf("servers: %v", got)
	}
	if got := complete(t, "ack", ""); !slices.Contains(got, "INC-12") {
		t.Errorf("incidents: %v", got)
	}
	if got := complete(t, "servers", "--project", ""); len(got) == 0 {
		t.Errorf("projects: %v", got)
	}
	if got := complete(t, "incidents", "--env", "st"); strings.Join(got, ",") != "staging" {
		t.Errorf("environments: %v", got)
	}
	if got := complete(t, "mute", "checkout-api-prod", ""); strings.Join(got, ",") != "1d,2h,30m,off" {
		t.Errorf("mute lengths: %v", got)
	}
	if got := complete(t, "open", "cre"); !slices.Contains(got, "credit") {
		t.Errorf("open: %v", got)
	}
	// Only the first argument is a server: nothing is offered after it.
	if got := complete(t, "server", "checkout-api-prod", ""); len(got) != 0 {
		t.Errorf("second argument: %v", got)
	}
}

func TestCompletionGivesNothingWhenSignedOut(t *testing.T) {
	t.Setenv("KIYESI_CONFIG", t.TempDir())
	keychain = noKeychain{}
	if got := complete(t, "server", ""); len(got) != 0 {
		t.Errorf("%v", got)
	}
}
