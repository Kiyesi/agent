package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// Signin is one SSH sign-in that worked, as SSH itself wrote it down.
type Signin struct {
	At      time.Time
	User    string
	Address string
	Method  string
	// Key is the fingerprint SSH logged for a key sign-in, or "".
	Key string
}

// acceptedKey is OpenSSH's line with the key it accepted, when it names one.
var acceptedKey = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+(?: [a-z0-9]+)?(?:: \S+ (SHA256:[A-Za-z0-9+/]{43}))?`)

// syslogLine is a line of /var/log/auth.log or /var/log/secure: the time
// (classic "Oct 24 09:12:01" or RFC 3339), the host, and the program.
var syslogLine = regexp.MustCompile(`^(\w{3} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)) \S+ sshd(?:-session)?\[\d+\]: (.*)$`)

// SigninsBetween reads the SSH sign-ins between from and to, at most limit,
// newest last: from the journal when there is one, else from the sign-in
// log files. It only reads; nothing leaves the server.
func SigninsBetween(ctx context.Context, sys *system.System, from, to time.Time, limit int) []Signin {
	var out []Signin
	if sys.Exec != nil && sys.Exec.Has("journalctl") {
		out = journalSignins(ctx, sys, from, to)
	}
	if len(out) == 0 {
		out = fileSignins(sys.FS, from, to)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func journalSignins(ctx context.Context, sys *system.System, from, to time.Time) []Signin {
	raw, err := sys.Exec.Run(ctx, "journalctl", "--output=json", "--no-pager", "--quiet", "--lines="+journalMax,
		"--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
		"--since=@"+strconv.FormatInt(from.Unix(), 10), "--until=@"+strconv.FormatInt(to.Unix(), 10),
		"--identifier=sshd", "--identifier=sshd-session")
	if err != nil && len(raw) == 0 {
		return nil
	}
	var out []Signin
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e struct {
			Message  any    `json:"MESSAGE"`
			Realtime string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		usec, err := strconv.ParseInt(e.Realtime, 10, 64)
		if err != nil {
			continue
		}
		msg, _ := e.Message.(string)
		if s, ok := parseAccepted(msg, time.UnixMicro(usec).UTC()); ok {
			out = append(out, s)
		}
	}
	return out
}

// fileSignins reads /var/log/auth.log (Debian, Ubuntu) or /var/log/secure
// (Red Hat), and the one before each, not the compressed older ones.
func fileSignins(fsys fs.FS, from, to time.Time) []Signin {
	var out []Signin
	for _, name := range []string{"var/log/auth.log.1", "var/log/auth.log", "var/log/secure.1", "var/log/secure"} {
		info, err := fs.Stat(fsys, name)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			continue
		}
		// A classic time has no year: it is the file's year, or the year
		// before for lines that would fall after the file last changed.
		year := info.ModTime().Year()
		for _, line := range strings.Split(string(data), "\n") {
			m := syslogLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			at, ok := lineTime(m[1], year, info.ModTime())
			if !ok || at.Before(from) || at.After(to) {
				continue
			}
			if s, ok := parseAccepted(m[2], at); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func lineTime(s string, year int, modified time.Time) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), true
	}
	// Written in the server's own time zone.
	t, err := time.ParseInLocation("Jan _2 15:04:05 2006", s+" "+strconv.Itoa(year), time.Local)
	if err != nil {
		return time.Time{}, false
	}
	if t.After(modified.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t.UTC(), true
}

func parseAccepted(msg string, at time.Time) (Signin, bool) {
	m := acceptedKey.FindStringSubmatch(msg)
	if m == nil {
		return Signin{}, false
	}
	ip, err := netip.ParseAddr(m[3])
	if err != nil || len(m[2]) > 64 {
		return Signin{}, false
	}
	return Signin{At: at, User: m[2], Address: ip.Unmap().String(), Method: m[1], Key: m[4]}, true
}
