package collect

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// LogLine is one line of output from the server. Its text is masked in
// send.Encode, the last step before anything leaves the server.
type LogLine struct {
	At time.Time `json:"at"`
	// Source names where it came from: a container, "nginx", "nginx error",
	// a site's own nginx log ("nginx shop.example.com", "nginx
	// shop.example.com error"), a systemd service, "kernel" or "docker".
	Source string `json:"source"`
	// Kind is container, file, journal or event.
	Kind string `json:"kind"`
	// Level is error, warn or info.
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Logs is one minute of log lines, oldest first, and how many were left
// out because the minute was over its limits.
type Logs struct {
	Lines   []LogLine `json:"lines"`
	Dropped int       `json:"dropped"`
}

// The limits on one server's minute (decisions log, 2026-10-10): beyond
// them lines are counted, not sent, so one noisy app cannot flood the
// service. Errors have a small reserve of their own, so a flood of
// ordinary lines cannot hide the one that matters.
const (
	MaxLogLines      = 2000
	MaxLogBytes      = 1 << 20
	MaxLineBytes     = 8 << 10
	errorReserve     = 200
	errorReserveSize = 64 << 10
)

// LogRules are the user's settings for what is sent.
type LogRules struct {
	// Exclude skips sources whose name matches one of these patterns,
	// such as "worker-*" or "cron".
	Exclude []string
	// Drop skips lines that contain one of these texts, such as "GET /health".
	Drop []string
}

func (r LogRules) excluded(source string) bool {
	for _, p := range r.Exclude {
		if ok, _ := path.Match(p, source); ok || p == source {
			return true
		}
	}
	return false
}

func (r LogRules) dropped(text string) bool {
	for _, d := range r.Drop {
		if d != "" && strings.Contains(text, d) {
			return true
		}
	}
	return false
}

// logBuffer gathers one minute's lines within the limits.
type logBuffer struct {
	rules        LogRules
	lines        []LogLine
	bytes        int
	reserveLines int
	reserveBytes int
	dropped      int
}

func (b *logBuffer) add(l LogLine) {
	l.Text = strings.TrimRight(l.Text, "\r\n")
	if strings.TrimSpace(l.Text) == "" || b.rules.excluded(l.Source) || b.rules.dropped(l.Text) {
		return
	}
	if len(l.Text) > MaxLineBytes {
		l.Text = cut(l.Text, MaxLineBytes) + " …[cut by Kiyesi]"
	}
	if l.Level == "" {
		l.Level = LevelOf(l.Text)
	}
	size := len(l.Text)
	switch {
	case len(b.lines)-b.reserveLines < MaxLogLines && b.bytes-b.reserveBytes+size <= MaxLogBytes:
	case l.Level == "error" && b.reserveLines < errorReserve && b.reserveBytes+size <= errorReserveSize:
		b.reserveLines++
		b.reserveBytes += size
	default:
		b.dropped++
		return
	}
	b.bytes += size
	b.lines = append(b.lines, l)
}

// take returns the minute's lines, oldest first, and empties the buffer.
// Lines over the limits become one line that says how many were left out.
func (b *logBuffer) take(now time.Time) *Logs {
	if len(b.lines) == 0 && b.dropped == 0 {
		return nil
	}
	out := &Logs{Lines: b.lines, Dropped: b.dropped}
	sort.SliceStable(out.Lines, func(i, j int) bool { return out.Lines[i].At.Before(out.Lines[j].At) })
	if b.dropped > 0 {
		out.Lines = append(out.Lines, LogLine{
			At: now, Source: "kiyesi", Kind: "event", Level: "warn",
			Text: "Kiyesi left out " + plural(b.dropped, "line", "lines") + " this minute: this server wrote more than " +
				strconv.Itoa(MaxLogLines) + " lines or 1 MB. Errors are kept first.",
		})
	}
	*b = logBuffer{rules: b.rules}
	return out
}

// cut shortens s to at most n bytes without splitting a character.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// How a line says its level, when it is not JSON: a level word in
// capitals, a key such as level=error, nginx's [error], or the opening
// of a crash.
var (
	errorWords = regexp.MustCompile(`(^|[^A-Za-z])(FATAL|PANIC|CRITICAL|CRIT|EMERG|ALERT|SEVERE|ERROR|ERR)([^A-Za-z]|$)|(?i)(level|lvl|severity)\s*[=:]\s*"?(fatal|panic|crit\w*|emerg\w*|alert|err\w*)|\[(emerg|alert|crit|error)\]|(?i)^\s*(error|fatal|panic)\b[:!]|^Traceback \(most recent call last\)|^\s*Uncaught |^panic: |^Exception in thread|^Unhandled (exception|rejection)`)
	warnWords  = regexp.MustCompile(`(^|[^A-Za-z])(WARN|WARNING)([^A-Za-z]|$)|(?i)(level|lvl|severity)\s*[=:]\s*"?warn\w*|\[warn\]|(?i)^\s*warning\b[:!]|^\(node:\d+\) \w*Warning`)
)

// LevelOf reads a line's level: from its JSON fields when it is JSON, then
// from an access log's status, then from words. Anything else is info.
func LevelOf(text string) string {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "{") {
		if lvl, ok := jsonLevel(t); ok {
			return lvl
		}
	}
	if r, ok := ParseAccessLine(t); ok {
		if r.Status >= 500 {
			return "error"
		}
		return "info"
	}
	switch {
	case errorWords.MatchString(t):
		return "error"
	case warnWords.MatchString(t):
		return "warn"
	}
	return "info"
}

// jsonLevel reads level, lvl, severity or levelname from a JSON line, as
// words or as pino's and bunyan's numbers.
func jsonLevel(t string) (string, bool) {
	var m map[string]any
	if json.Unmarshal([]byte(t), &m) != nil {
		return "", false
	}
	// A request's own status comes first: Caddy marks every request,
	// even a 502, with "level":"info".
	if s, ok := m["status"].(float64); ok && s >= 100 && s < 600 {
		if _, isRequest := m["request"]; isRequest {
			if s >= 500 {
				return "error", true
			}
			return "info", true
		}
	}
	for _, k := range []string{"level", "lvl", "severity", "levelname", "log.level", "loglevel"} {
		switch v := m[k].(type) {
		case float64:
			switch {
			case v >= 50:
				return "error", true
			case v >= 40:
				return "warn", true
			default:
				return "info", true
			}
		case string:
			return levelWord(v), true
		}
	}
	// Caddy's access lines carry a status rather than a level.
	if s, ok := m["status"].(float64); ok && s >= 500 {
		return "error", true
	}
	return "", false
}

func levelWord(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "fatal", "panic", "critical", "crit", "emerg", "emergency", "alert", "error", "err", "severe", "dpanic":
		return "error"
	case "warn", "warning":
		return "warn"
	}
	return "info"
}

// priorityLevel turns a syslog priority (0 emergency to 7 debug) into a level.
func priorityLevel(p int) string {
	switch {
	case p <= 3:
		return "error"
	case p == 4:
		return "warn"
	}
	return "info"
}
