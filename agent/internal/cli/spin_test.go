package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	xterm "github.com/charmbracelet/x/term"
)

// lockedBuffer is a terminal for the tests: the animation writes from its own goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func asTerminal(t *testing.T, delay time.Duration) {
	t.Helper()
	old, oldDelay := stderrIsTerminal, spinDelay
	stderrIsTerminal = func(io.Writer, []string) bool { return true }
	spinDelay = delay
	t.Cleanup(func() { stderrIsTerminal, spinDelay = old, oldDelay })
}

func TestTheWatchfulDotWhileWaitingThenErasedBeforeTheResult(t *testing.T) {
	asTerminal(t, 0)
	var term lockedBuffer
	s := newSpinner(IO{Err: &term})
	s.start("Reading incidents")
	time.Sleep(300 * time.Millisecond)
	out := guarded{&term, s}
	_, _ = out.Write([]byte("INC-12  Critical\n"))
	got := term.String()
	for _, want := range []string{"\x1b[?25l", "ˊ\x1b[38;2;255;194;75m•\x1b[39m", "Reading incidents…", "\r\x1b[2K\x1b[?25hINC-12  Critical\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	s.stop() // twice is fine
	// The dot glances: over one cycle it rests in the middle, then looks left and right.
	places := map[string]bool{}
	for i := range glance {
		f := (&spinner{words: "x"}).frame(i, 0)
		places[f[:strings.Index(f, accent)]] = true
	}
	if len(places) != 3 {
		t.Errorf("the dot sits in %d places, not 3", len(places))
	}
}

func TestQuickAnswersNeverFlicker(t *testing.T) {
	asTerminal(t, time.Second)
	var term lockedBuffer
	s := newSpinner(IO{Err: &term})
	s.start("Reading incidents")
	_, _ = guarded{&term, s}.Write([]byte("done\n"))
	if got := term.String(); got != "done\n" {
		t.Errorf("drew something for a quick answer: %q", got)
	}
}

func TestNoColourWhenAskedButTheDotStillShows(t *testing.T) {
	asTerminal(t, 0)
	var term lockedBuffer
	s := newSpinner(IO{Err: &term, Environ: []string{"NO_COLOR=1"}})
	s.start("Checking this server")
	time.Sleep(150 * time.Millisecond)
	s.stop()
	got := term.String()
	if strings.Contains(got, "\x1b[38;") || !strings.Contains(got, "ˊ• ") || !strings.Contains(got, "Checking this server…") {
		t.Errorf("%q", got)
	}
}

func TestTheDotSaysHowLongAfterAFewSeconds(t *testing.T) {
	s := &spinner{words: "Reading incidents"}
	if f := s.frame(0, 2*time.Second); strings.Contains(f, " s") {
		t.Errorf("too soon: %q", f)
	}
	if f := s.frame(0, 5*time.Second); !strings.HasSuffix(f, "Reading incidents… 5 s") {
		t.Errorf("%q", f)
	}
}

func TestNoDotForScriptsJSONOrWhenPiped(t *testing.T) {
	signInForTest(t)
	asTerminal(t, 0)
	var term lockedBuffer
	var out bytes.Buffer
	code := Execute([]string{"servers", "--json"}, IO{Out: &out, Err: &term, Environ: []string{"NO_COLOR=1"}})
	if code != ExitOK || strings.Contains(term.String(), "Reading") {
		t.Errorf("--json drew the dot: %q", term.String())
	}
	stderrIsTerminal = func(io.Writer, []string) bool { return false }
	code = Execute([]string{"servers"}, IO{Out: &out, Err: &term})
	if code != ExitOK || strings.Contains(term.String(), "Reading") {
		t.Errorf("piped drew the dot: %q", term.String())
	}
}

func TestTheDotNamesWhatItIsDoing(t *testing.T) {
	signInForTest(t)
	asTerminal(t, 0)
	var term lockedBuffer
	var out bytes.Buffer
	// The fake API answers at once, but with no delay the first frame is drawn before it.
	code := Execute([]string{"incident", "INC-11"}, IO{Out: &out, Err: &term, Environ: []string{"NO_COLOR=1"}})
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if got := term.String(); got != "" && !strings.Contains(got, "Reading INC-11…") {
		t.Errorf("%q", got)
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("the result has terminal codes: %q", out.String())
	}
}

func TestVersionCarriesTheMarkAndTheCompanyLine(t *testing.T) {
	old := stdoutIsTerminal
	stdoutIsTerminal = func(IO) bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = old })
	_, out, _ := runCLI(t, "version")
	if !strings.HasPrefix(out, " ˊ•  kiyesi ") || !strings.HasSuffix(out, "\n     © "+fmt.Sprint(time.Now().Year())+" Kiyesi Technologies · kiyesi.dev\n") {
		t.Errorf("%q", out)
	}
	_, help, _ := runCLI(t, "--help")
	_, sub, _ := runCLI(t, "servers", "--help")
	if !strings.Contains(help, "Kiyesi Technologies") || strings.Contains(sub, "Kiyesi Technologies") {
		t.Errorf("the company line belongs at the foot of kiyesi --help only")
	}
}

func TestTheGuardKeepsTheTerminalVisibleUnderneath(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := &spinner{quit: make(chan struct{}), done: make(chan struct{})}
	g := s.guard(f)
	// What the colour library and kiyesi watch look for: the same file descriptor.
	tf, ok := g.(xterm.File)
	if !ok || tf.Fd() != f.Fd() {
		t.Fatalf("the guard hides the file: %T", g)
	}
	// Every way of writing stops the animation first.
	for _, write := range []func() error{
		func() error { _, err := g.Write([]byte("a")); return err },
		func() error { _, err := io.WriteString(g, "b"); return err },
		func() error { _, err := io.Copy(g, strings.NewReader("c")); return err },
	} {
		s = &spinner{quit: make(chan struct{}), done: make(chan struct{})}
		g = s.guard(f)
		if err := write(); err != nil || !s.stopped {
			t.Errorf("wrote without stopping the animation: %v", err)
		}
	}
	if _, ok := s.guard(&bytes.Buffer{}).(guarded); !ok {
		t.Error("a buffer is guarded as a file")
	}
}
