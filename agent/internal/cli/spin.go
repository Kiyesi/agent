package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

// The watchful dot: while a command waits on the service or the scan, the
// mark from the brand (an accent over an amber dot) glances left and right
// beside a few plain words, such as "Reading incidents…". It appears only
// for a person at a terminal, after a short wait so quick answers never
// flicker, on the error stream so piped output and --json never see it,
// and it is erased the moment the command prints anything.

const (
	spinTick = 110 * time.Millisecond
	accent   = "ˊ"
	dot      = "•"
)

// spinDelay is how long a command may take before the dot appears. Tests change it.
var spinDelay = 200 * time.Millisecond

// Where the dot sits in each frame: it rests, glances one way, rests, glances the other.
var glance = []int{1, 1, 1, 0, 0, 1, 1, 1, 2, 2}

type spinner struct {
	out     io.Writer // the terminal itself, never the guarded writers
	color   bool
	mu      sync.Mutex
	words   string
	started bool
	stopped bool
	quit    chan struct{}
	done    chan struct{}
	now     func() time.Time
	delay   time.Duration
}

// stderrIsTerminal says whether a person can see the animation. Tests replace it.
var stderrIsTerminal = func(w io.Writer, environ []string) bool {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(f.Fd()) {
		return false
	}
	for _, e := range environ {
		if e == "TERM=dumb" || strings.HasPrefix(e, "KIYESI_NO_SPINNER=") || strings.HasPrefix(e, "CI=") {
			return false
		}
	}
	return true
}

func newSpinner(io IO) *spinner {
	if !stderrIsTerminal(io.Err, io.Environ) {
		return nil
	}
	color := true
	for _, e := range io.Environ {
		if strings.HasPrefix(e, "NO_COLOR=") {
			color = false
		}
	}
	return &spinner{out: io.Err, color: color, quit: make(chan struct{}), done: make(chan struct{}), now: time.Now, delay: spinDelay}
}

// frame draws the mark at one moment, with the words and, after a few seconds, how long.
func (s *spinner) frame(i int, waited time.Duration) string {
	p := glance[i%len(glance)]
	mark := accent + dot
	if s.color {
		// The dot in Amber (#FFC24B), the accent in the terminal's own colour.
		mark = accent + "\x1b[38;2;255;194;75m" + dot + "\x1b[39m"
	}
	line := strings.Repeat(" ", p) + mark + strings.Repeat(" ", 2-p) + " " + s.words + "…"
	if waited >= 3*time.Second {
		line += fmt.Sprintf(" %d s", int(waited.Seconds()))
	}
	return "\r\x1b[2K " + line
}

// start shows the animation after a short wait, until stop.
func (s *spinner) start(words string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	s.started, s.words = true, words
	s.mu.Unlock()
	go func() {
		defer close(s.done)
		begin := s.now()
		select {
		case <-s.quit:
			return
		case <-time.After(s.delay):
		}
		fmt.Fprint(s.out, "\x1b[?25l") // hide the cursor while it moves
		t := time.NewTicker(spinTick)
		defer t.Stop()
		for i := 0; ; i++ {
			s.mu.Lock()
			fmt.Fprint(s.out, s.frame(i, s.now().Sub(begin)))
			s.mu.Unlock()
			select {
			case <-s.quit:
				fmt.Fprint(s.out, "\r\x1b[2K\x1b[?25h") // erase the line, show the cursor
				return
			case <-t.C:
			}
		}
	}()
}

// stop erases the animation, once, before anything else is printed.
func (s *spinner) stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	started := s.started
	s.mu.Unlock()
	if started {
		close(s.quit)
		<-s.done
	}
}

// guarded writes to w only after the animation is gone.
type guarded struct {
	w io.Writer
	s *spinner
}

func (g guarded) Write(p []byte) (int, error) {
	g.s.stop()
	return g.w.Write(p)
}

// guardedFile is guarded for a real terminal or file. It keeps the file
// underneath, so every "is this a terminal?" check (colours, kiyesi watch,
// kiyesi version) still sees it; every way of writing erases the animation first.
type guardedFile struct {
	*os.File
	s *spinner
}

func (g guardedFile) Write(p []byte) (int, error) {
	g.s.stop()
	return g.File.Write(p)
}

func (g guardedFile) WriteString(str string) (int, error) {
	g.s.stop()
	return g.File.WriteString(str)
}

func (g guardedFile) ReadFrom(r io.Reader) (int64, error) {
	g.s.stop()
	return g.File.ReadFrom(r)
}

// guard wraps w so the animation is erased before anything is written to it.
func (s *spinner) guard(w io.Writer) io.Writer {
	if f, ok := w.(*os.File); ok {
		return guardedFile{f, s}
	}
	return guarded{w, s}
}

// isTerminal says whether w is a terminal, seeing through the guard.
func isTerminal(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(f.Fd())
}

// Commands that draw their own screen, wait on a person, stream, or answer
// at once: no animation.
var noSpinner = map[string]bool{
	"kiyesi login": true, "kiyesi logout": true, "kiyesi watch": true, "kiyesi agent": true,
	"kiyesi connect": true, "kiyesi run": true, "kiyesi uninstall": true, "kiyesi version": true,
	"kiyesi help": true, "kiyesi completion": true, "kiyesi __complete": true, "kiyesi __completeNoDesc": true,
	"kiyesi open": true, "kiyesi fix undo": true, "kiyesi mcp": true, "kiyesi credit topup": true, "kiyesi team use": true,
}

// spinWords is what each command is doing, in a few plain words.
var spinWords = map[string]string{
	"kiyesi":             "Looking at what needs you",
	"kiyesi scan":        "Checking this server",
	"kiyesi fix":         "Checking what Kiyesi can fix",
	"kiyesi servers":     "Reading your servers",
	"kiyesi server":      "Reading %s",
	"kiyesi findings":    "Reading findings",
	"kiyesi incidents":   "Reading incidents",
	"kiyesi incident":    "Reading %s",
	"kiyesi mine":        "Reading your work",
	"kiyesi ack":         "Acknowledging %s",
	"kiyesi resolve":     "Marking %s fixed",
	"kiyesi assign":      "Giving %s to someone",
	"kiyesi metrics":     "Reading metrics",
	"kiyesi logs":        "Searching logs",
	"kiyesi errors":      "Reading browser errors",
	"kiyesi traces":      "Reading requests",
	"kiyesi trace":       "Following %s",
	"kiyesi uptime":      "Reading uptime checks",
	"kiyesi history":     "Reading history",
	"kiyesi deploys":     "Reading deploys",
	"kiyesi jobs":        "Reading scheduled jobs",
	"kiyesi databases":   "Reading databases",
	"kiyesi costs":       "Weighing costs",
	"kiyesi datamap":     "Mapping where your data is",
	"kiyesi tips":        "Reading tips",
	"kiyesi advisories":  "Reading advisories",
	"kiyesi alerts":      "Reading alerts",
	"kiyesi alerts test": "Sending test messages",
	"kiyesi team":        "Reading your team",
	"kiyesi activity":    "Reading the activity log",
	"kiyesi credit":      "Reading your credit",
	"kiyesi reports":     "Reading reports",
	"kiyesi report":      "Making the report",
	"kiyesi report card": "Counting last week",
	"kiyesi update":      "Checking for a newer kiyesi",
	"kiyesi whoami":      "Reading your access",
	"kiyesi preflight":   "Checking whether it is safe to deploy",
	"kiyesi explain":     "Writing %s in plain words",
	"kiyesi drill":       "Sending the practice incident, one step a minute",
	"kiyesi passport":    "Writing the passport of %s",
}

// spinFor starts the animation for the command about to run, unless it is
// one that should not have it, or its output is for a script.
func (s *spinner) spinFor(cmd *cobra.Command, args []string) {
	if s == nil || noSpinner[cmd.CommandPath()] {
		return
	}
	for _, name := range []string{"json", "follow"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Value.String() == "true" {
			return
		}
	}
	words, ok := spinWords[cmd.CommandPath()]
	if !ok {
		words = "Working"
	}
	if strings.Contains(words, "%s") {
		if len(args) == 0 {
			words = strings.TrimSuffix(strings.Replace(words, "%s", "", 1), " ")
		} else {
			words = fmt.Sprintf(words, args[0])
		}
	}
	s.start(words)
}
