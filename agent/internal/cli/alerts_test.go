package cli

import (
	"strings"
	"testing"
)

func TestAlertsShowsChannelsAndWhatIsOpen(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "alerts")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"slack", "#ops", "ready", "waiting for Start in Telegram", "1 alert open:", "checkout-api-prod: Redis is open to the internet on port 6379"} {
		if !strings.Contains(out, want) {
			t.Errorf("alerts output is missing %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "alerts", "test")
	if code != ExitOK || !strings.Contains(out, "SENT  slack #ops") || !strings.Contains(out, "SKIP  telegram") {
		t.Errorf("alerts test: exit %d:\n%s", code, out)
	}
}

func TestMuteAlwaysEnds(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "mute", "checkout-api-prod", "30m")
	if code != ExitOK || !strings.Contains(out, "muted until") || !strings.Contains(out, "kiyesi mute checkout-api-prod off") {
		t.Errorf("mute: exit %d: %s", code, out)
	}
	code, _, errOut := runCLI(t, "mute", "checkout-api-prod", "forever")
	if code != ExitUsage || !strings.Contains(errOut, "Every mute ends") {
		t.Errorf("mute forever: exit %d: %s", code, errOut)
	}
	if code, out, _ := runCLI(t, "mute", "checkout-api-prod", "off"); code != ExitOK || !strings.Contains(out, "on again") {
		t.Errorf("unmute: exit %d: %s", code, out)
	}
}

func TestUptimeListsAndAdds(t *testing.T) {
	signInForTest(t)
	code, out, _ := runCLI(t, "uptime")
	if code != ExitOK || !strings.Contains(out, "Shop") || !strings.Contains(out, "DOWN") || !strings.Contains(out, "no answer within 10 seconds") {
		t.Errorf("uptime: exit %d:\n%s", code, out)
	}
	if code, out, _ := runCLI(t, "uptime", "add", "https://example.com/health"); code != ExitOK || !strings.Contains(out, "every minute") {
		t.Errorf("uptime add: exit %d: %s", code, out)
	}
	code, _, errOut := runCLI(t, "uptime", "add", "http://169.254.169.254/")
	if code != ExitUsage || !strings.Contains(errOut, "private network") {
		t.Errorf("uptime add private: exit %d: %s", code, errOut)
	}
}
