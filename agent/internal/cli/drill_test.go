package cli

import (
	"strings"
	"testing"
)

func TestDrillShowsWhoWasReachedAndWhichChannelFailed(t *testing.T) {
	signInForTest(t)
	code, out, errOut := runCLI(t, "drill")
	if code != ExitOK {
		t.Fatalf("%d %s", code, errOut)
	}
	for _, want := range []string{
		"Fire drill, ",
		"after  15 min  Ifeoma Nwosu         Slack, delivered in 2 s, acknowledged in 1 min",
		"after  30 min  Ada Obi              NOT REACHED: Telegram was not delivered: the bot is no longer in your chat",
		"1 of 2 steps reached a person.",
		"kiyesi drill --last",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, out, _ := runCLI(t, "drill", "--last", "--json"); code != ExitOK || !strings.Contains(out, `"summary": "1 of 2 steps`) {
		t.Errorf("--last --json: %d %s", code, out)
	}
}
