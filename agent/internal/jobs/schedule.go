package jobs

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Schedule is when a job is expected to run, as found in a crontab or a
// systemd timer that calls kiyesi job done.
type Schedule struct {
	Name     string `json:"name"`
	Source   string `json:"source"` // "cron" or "systemd"
	Schedule string `json:"schedule"`
	NextAt   string `json:"next_at,omitempty"`
}

// The name kiyesi job done is given in a command line.
var runName = regexp.MustCompile(`kiyesi\s+job\s+done\s+(?:.*?\s)?--name(?:=|\s+)["']?([A-Za-z0-9][A-Za-z0-9._-]{0,79})`)

// Cron is a parsed five-field schedule.
type Cron struct {
	minute, hour, dom, month, dow uint64
	domAny, dowAny                bool
}

var macros = map[string]string{
	"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
	"@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}
var monthNames = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

func field(s string, lo, hi int, names []string, nameBase int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(s, ",") {
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 {
				return 0, fmt.Errorf("bad step in %q", s)
			}
			step, part = n, part[:i]
		}
		start, end := lo, hi
		if part != "*" {
			a, b, isRange := strings.Cut(part, "-")
			var err error
			if start, err = value(a, names, nameBase); err != nil {
				return 0, err
			}
			end = start
			if isRange {
				if end, err = value(b, names, nameBase); err != nil {
					return 0, err
				}
			} else if step > 1 {
				end = hi
			}
		}
		if start < lo || end > hi || start > end {
			return 0, fmt.Errorf("%q is out of range", s)
		}
		for v := start; v <= end; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

func value(s string, names []string, base int) (int, error) {
	for i, n := range names {
		if strings.EqualFold(s, n) {
			return i + base, nil
		}
	}
	return strconv.Atoi(s)
}

// ParseCron reads "m h dom mon dow" or a macro such as @daily.
func ParseCron(spec string) (Cron, error) {
	if m, ok := macros[strings.ToLower(spec)]; ok {
		spec = m
	}
	f := strings.Fields(spec)
	if len(f) != 5 {
		return Cron{}, fmt.Errorf("%q is not a five-field schedule", spec)
	}
	var c Cron
	var err error
	if c.minute, err = field(f[0], 0, 59, nil, 0); err != nil {
		return c, err
	}
	if c.hour, err = field(f[1], 0, 23, nil, 0); err != nil {
		return c, err
	}
	if c.dom, err = field(f[2], 1, 31, nil, 0); err != nil {
		return c, err
	}
	if c.month, err = field(f[3], 1, 12, monthNames, 1); err != nil {
		return c, err
	}
	if c.dow, err = field(strings.ReplaceAll(f[4], "7", "0"), 0, 6, dayNames, 0); err != nil {
		return c, err
	}
	c.domAny, c.dowAny = f[2] == "*", f[4] == "*"
	return c, nil
}

func (c Cron) day(t time.Time) bool {
	dom := c.dom&(1<<uint(t.Day())) != 0
	dow := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	default:
		return dom || dow // as cron does when both are set
	}
}

// Next is the first time after t the schedule runs, in t's time zone, or
// the zero time when it never does within a year.
func (c Cron) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(1, 0, 1)
	for t.Before(limit) {
		if c.month&(1<<uint(t.Month())) == 0 || !c.day(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		if c.hour&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
			continue
		}
		if c.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// FromCrontab finds the jobs in a crontab that call kiyesi job done. withUser says
// whether lines carry a user field, as /etc/crontab and /etc/cron.d do.
func FromCrontab(text string, withUser bool, now time.Time) []Schedule {
	var out []Schedule
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := runName.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		f := strings.Fields(line)
		spec := ""
		if strings.HasPrefix(f[0], "@") {
			spec = f[0]
		} else if len(f) >= 6 {
			spec = strings.Join(f[:5], " ")
		}
		c, err := ParseCron(spec)
		if err != nil {
			continue
		}
		s := Schedule{Name: m[1], Source: "cron", Schedule: spec}
		if next := c.Next(now); !next.IsZero() {
			s.NextAt = next.UTC().Format(time.RFC3339)
		}
		out = append(out, s)
	}
	return out
}

// Runner runs a read-only command, such as systemctl show.
type Runner interface {
	Has(name string) bool
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Find looks for jobs that call kiyesi job done in the crontabs and in the
// systemd services started by a timer, and works out when each runs next.
func Find(ctx context.Context, fsys fs.FS, run Runner, now time.Time) []Schedule {
	var out []Schedule
	read := func(p string) string {
		data, err := fs.ReadFile(fsys, p)
		if err != nil || len(data) > 256*1024 {
			return ""
		}
		return string(data)
	}
	out = append(out, FromCrontab(read("etc/crontab"), true, now)...)
	for _, dir := range []string{"etc/cron.d"} {
		if entries, err := fs.ReadDir(fsys, dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					out = append(out, FromCrontab(read(path.Join(dir, e.Name())), true, now)...)
				}
			}
		}
	}
	for _, dir := range []string{"var/spool/cron/crontabs", "var/spool/cron"} {
		if entries, err := fs.ReadDir(fsys, dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					out = append(out, FromCrontab(read(path.Join(dir, e.Name())), false, now)...)
				}
			}
		}
	}
	// systemd: a service in /etc/systemd/system that calls kiyesi job done,
	// started by the timer of the same name.
	if entries, err := fs.ReadDir(fsys, "etc/systemd/system"); err == nil && run != nil && run.Has("systemctl") {
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			unit := read(path.Join("etc/systemd/system", e.Name()))
			var name string
			for _, l := range strings.Split(unit, "\n") {
				// The job's own ExecStart= runs it; ExecStopPost= tells Kiyesi.
				if t := strings.TrimSpace(l); strings.HasPrefix(t, "ExecStopPost=") || strings.HasPrefix(t, "ExecStart=") {
					if m := runName.FindStringSubmatch(l); m != nil {
						name = m[1]
					}
				}
			}
			timer := strings.TrimSuffix(e.Name(), ".service") + ".timer"
			if name == "" || read(path.Join("etc/systemd/system", timer)) == "" {
				continue
			}
			s := Schedule{Name: name, Source: "systemd", Schedule: onCalendar(read(path.Join("etc/systemd/system", timer)))}
			// As systemctl prints it, in the server's own time zone: "Mon 2026-10-12 03:37:21 UTC".
			if b, err := run.Run(ctx, "systemctl", "show", timer, "--property=NextElapseUSecRealtime", "--value"); err == nil {
				if at, ok := parseElapse(string(b)); ok {
					s.NextAt = at.UTC().Format(time.RFC3339)
				}
			}
			out = append(out, s)
		}
	}
	// One schedule per name: the first found.
	seen := map[string]bool{}
	var unique []Schedule
	for _, s := range out {
		if !seen[s.Name] {
			seen[s.Name] = true
			unique = append(unique, s)
		}
	}
	return unique
}

func onCalendar(timer string) string {
	for _, l := range strings.Split(timer, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "OnCalendar="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseElapse reads systemctl's next elapse: "Mon 2026-10-12 03:37:21 UTC",
// or "@1791689400" where systemd prints Unix time. The zone is the server's
// own (the agent runs there), so its abbreviation means the local offset.
func parseElapse(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if secs, err := strconv.ParseInt(strings.TrimPrefix(v, "@"), 10, 64); err == nil && secs > 0 {
		return time.Unix(secs, 0), true
	}
	if t, err := time.ParseInLocation("Mon 2006-01-02 15:04:05 MST", v, time.Local); err == nil {
		return t, true
	}
	return time.Time{}, false
}
