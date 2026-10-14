package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

func watchFor(t *testing.T) watchModel {
	t.Helper()
	signInForTest(t)
	c, err := signedIn()
	if err != nil {
		t.Fatal(err)
	}
	return watchModel{ctx: context.Background(), c: c, dashboard: "https://app.example.test", clock: time.Now}
}

func press(t *testing.T, m watchModel, key string) (watchModel, tea.Cmd) {
	t.Helper()
	var k tea.KeyPressMsg
	switch key {
	case "down":
		k = tea.KeyPressMsg{Code: tea.KeyDown}
	case "enter":
		k = tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		k = tea.KeyPressMsg{Code: tea.KeyEscape}
	default:
		k = tea.KeyPressMsg{Code: rune(key[0]), Text: key}
	}
	next, cmd := m.Update(k)
	return next.(watchModel), cmd
}

func TestWatchShowsWhatNeedsYouIncidentsAndServers(t *testing.T) {
	m := watchFor(t)
	next, cmd := m.Update(m.Init()())
	m = next.(watchModel)
	if cmd == nil {
		t.Error("no refresh was scheduled")
	}
	out := m.render()
	for _, want := range []string{
		"KIYESI WATCH  updated",
		// Critical and nobody on it comes first.
		"NEEDS YOU NOW\n  INC-11 is open: storefront-web: errors in users' browsers. Nobody has acknowledged it.\n  INC-12 is open:",
		"OPEN INCIDENTS\n> INC-12",
		"checkout-api-prod        D 55",
		"enter details",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestWatchOpensAnIncidentsEvidenceAndAServersFindings(t *testing.T) {
	m := watchFor(t)
	next, _ := m.Update(m.Init()())
	m = next.(watchModel)
	// Down to INC-11, the incident the fake API has evidence for.
	for m.cursor < len(m.data.incidents) && m.data.incidents[m.cursor].Ref != "INC-11" {
		m, _ = press(t, m, "down")
	}
	m, cmd := press(t, m, "enter")
	if cmd == nil {
		t.Fatal("enter did nothing")
	}
	next, _ = m.Update(cmd())
	m = next.(watchModel)
	out := m.render()
	for _, want := range []string{"INC-11  storefront-web", "Likely source: frontend, confirmed", "kiyesi ack INC-11"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	var opened string
	openBrowser = func(u string) { opened = u }
	m, _ = press(t, m, "o")
	if opened != "https://app.example.test/incident/?id=INC-11" {
		t.Errorf("opened %q", opened)
	}
	m, _ = press(t, m, "esc")
	if m.detail != nil {
		t.Error("esc did not go back")
	}
	for m.cursor < m.rows()-1 && m.cursor < len(m.data.incidents) {
		m, _ = press(t, m, "down")
	}
	m, cmd = press(t, m, "enter")
	next, _ = m.Update(cmd())
	out = next.(watchModel).render()
	if !strings.Contains(out, "checkout-api-prod  findings") || !strings.Contains(out, "CRITICAL Redis is open to the internet") {
		t.Errorf("server findings:\n%s", out)
	}
	if _, cmd := press(t, m, "q"); cmd == nil {
		t.Error("q did not quit")
	}
}

func TestWatchPipedPrintsOnceAndStops(t *testing.T) {
	signInForTest(t)
	done := make(chan struct{})
	var code int
	var out string
	go func() {
		code, out, _ = runCLI(t, "watch")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("kiyesi watch kept running when piped")
	}
	if code != ExitOK || !strings.Contains(out, "OPEN INCIDENTS") || strings.Contains(out, "q quit") || strings.Contains(out, "> ") {
		t.Errorf("%d:\n%s", code, out)
	}
}

func TestWatchAsksTheServiceFourTimesARefresh(t *testing.T) {
	m := watchFor(t)
	apiRequests.Store(0)
	m.fetch()
	if n := apiRequests.Load(); n != 4 {
		t.Errorf("one refresh made %d requests, not 4", n)
	}
}
