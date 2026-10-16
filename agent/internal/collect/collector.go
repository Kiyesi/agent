package collect

import (
	"context"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// Metrics is one minute of measurements. Rates and percentages are nil on
// the first minute, when there is nothing to compare with yet.
type Metrics struct {
	CPUPercent *float64        `json:"cpu_percent"`
	Load1      *float64        `json:"load1"`
	Memory     *Memory         `json:"memory"`
	Disks      []Disk          `json:"disks"`
	Net        *Net            `json:"net"`
	Containers []Container     `json:"containers"`
	HTTP       []EndpointStats `json:"http"`
	// HTTPSource names where requests were read from, such as
	// "/var/log/nginx/access.log" or "caddy (container)".
	HTTPSource string `json:"http_source,omitempty"`
	// CPUCores is how many CPU cores the server has, for cost watch.
	CPUCores int `json:"cpu_cores,omitempty"`
}

type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	SwapUsedBytes  uint64 `json:"swap_used_bytes"`
}

type Disk struct {
	Mount      string `json:"mount"`
	UsedBytes  uint64 `json:"used_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
}

type Net struct {
	RxBytesPerSec float64 `json:"rx_bps"`
	TxBytesPerSec float64 `json:"tx_bps"`
}

type Container struct {
	Name string `json:"name"`
	// CPUPercent is the share of the whole server, so it adds up with the
	// server's own figure.
	CPUPercent    *float64 `json:"cpu_percent"`
	MemBytes      *uint64  `json:"mem_bytes"`
	MemLimitBytes *uint64  `json:"mem_limit_bytes"`
}

// Event is something that happened on the server.
type Event struct {
	// Kind is restart, image_changed, oom_kill or signin.
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	// For a sign-in: the address it came from, and when.
	Address string `json:"address,omitempty"`
	At      string `json:"at,omitempty"`
}

// AccessLogs are the host files read for requests, when they exist.
var AccessLogs = []string{"var/log/nginx/access.log"}

// ErrorLogs are the host web server's error logs, sent as log lines only.
var ErrorLogs = []string{"var/log/nginx/error.log"}

// fileSource names a log file in the Logs screen.
func fileSource(p string) string {
	if strings.HasSuffix(p, "error.log") {
		return "nginx error"
	}
	return "nginx"
}

// webServerImage picks the containers whose output is a web server's access log.
var webServerImage = regexp.MustCompile(`(^|/)(nginx|caddy|openresty|traefik)(:|@|$)`)

type containerState struct {
	id, imageID, image, startedAt string
	restarts                      int
	oom                           bool
	cpuUsec                       uint64
}

// Collector keeps what it needs between minutes.
type Collector struct {
	Sys *system.System

	at         time.Time
	cpu        cpuTimes
	net        netBytes
	oomKills   uint64
	hasOOM     bool
	containers map[string]containerState
	// Where each log file was read up to, and each container's output.
	fileOffset map[string]int64
	logSince   map[string]time.Time

	// Logs, when true, also collects log lines (agent mode), within
	// the limits, following Rules and Journal.
	Logs    bool
	Rules   LogRules
	Journal JournalRules
	journal journal
	buf     logBuffer

	// Signins, when set, watches for SSH sign-ins not seen before.
	Signins *SigninWatch
}

// TakeLogs returns the log lines gathered since the last call, or nil.
func (c *Collector) TakeLogs() *Logs {
	return c.buf.take(c.Sys.Now())
}

func pct(v float64) *float64 {
	r := math.Round(v*10) / 10
	return &r
}

// Collect takes this minute's measurements and the events since the last.
func (c *Collector) Collect(ctx context.Context) (Metrics, []Event) {
	now := c.Sys.Now()
	first := c.at.IsZero()
	secs := now.Sub(c.at).Seconds()
	var m Metrics
	var events []Event

	cpu, cores, cpuErr := readCPU(c.Sys.FS)
	if cpuErr == nil && !first && cpu.total > c.cpu.total {
		m.CPUPercent = pct(float64(cpu.busy-c.cpu.busy) / float64(cpu.total-c.cpu.total) * 100)
	}
	if l, ok := readLoad1(c.Sys.FS); ok {
		m.Load1 = &l
	}
	if mem, err := readMem(c.Sys.FS); err == nil && mem.total > 0 {
		m.Memory = &Memory{
			TotalBytes:     mem.total,
			UsedBytes:      mem.total - min(mem.available, mem.total),
			SwapTotalBytes: mem.swapTotal,
			SwapUsedBytes:  mem.swapTotal - min(mem.swapFree, mem.swapTotal),
		}
	}
	if mounts, err := system.DataMounts(c.Sys.FS); err == nil && c.Sys.Statfs != nil {
		for _, mt := range mounts {
			u, err := c.Sys.Statfs(mt.Point)
			if err != nil || u.TotalBytes == 0 {
				continue
			}
			// Like df: the space a normal user can fill.
			used := u.TotalBytes - u.FreeBytes
			m.Disks = append(m.Disks, Disk{Mount: mt.Point, UsedBytes: used, TotalBytes: used + u.AvailBytes})
		}
	}
	net, netErr := readNet(c.Sys.FS)
	if netErr == nil && !first && secs > 0 && net.rx >= c.net.rx && net.tx >= c.net.tx {
		m.Net = &Net{RxBytesPerSec: math.Round(float64(net.rx-c.net.rx) / secs), TxBytesPerSec: math.Round(float64(net.tx-c.net.tx) / secs)}
	}
	if kills, ok := readOOMKills(c.Sys.FS); ok {
		if c.hasOOM && kills > c.oomKills {
			events = append(events, Event{Kind: "oom_kill", Detail: plural(int(min(kills-c.oomKills, 1000)), "process", "processes") + " killed for using too much memory"})
		}
		c.oomKills, c.hasOOM = kills, true
	}

	var list []system.Container
	if c.Sys.Docker != nil {
		list, _ = c.Sys.Docker.Containers(ctx)
	}
	m.Containers, events = c.readContainers(list, secs, first, cores, events)
	if cpuErr == nil && cores > 0 {
		m.CPUCores = cores
	}
	c.buf.rules = c.Rules
	var reqs Requests
	m.HTTPSource = c.readAccessLogs(ctx, now, list, &reqs)
	m.HTTP = reqs.Stats()
	if c.Logs {
		c.journal.read(ctx, c.Sys, c.Journal, now, &c.buf)
		journalOn := c.Journal.On && c.Sys.Exec != nil && c.Sys.Exec.Has("journalctl")
		for _, e := range events {
			// The kernel's own line says the same, when the system log is read.
			if e.Kind == "oom_kill" && e.Subject == "" && journalOn {
				continue
			}
			c.buf.add(eventLine(now, e))
		}
	}

	if c.Signins != nil {
		events = append(events, c.Signins.Read(ctx, c.Sys, now)...)
	}
	c.at, c.cpu, c.net = now, cpu, net
	return m, events
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func (c *Collector) readContainers(list []system.Container, secs float64, first bool, cores int, events []Event) ([]Container, []Event) {
	seen := map[string]containerState{}
	var out []Container
	for _, ct := range list {
		st := containerState{id: ct.ID, imageID: ct.ImageID, image: ct.Image, startedAt: ct.StartedAt, restarts: ct.RestartCount, oom: ct.OOMKilled}
		if prev, ok := c.containers[ct.Name]; ok && !first {
			switch {
			case prev.imageID != "" && ct.ImageID != "" && prev.imageID != ct.ImageID:
				events = append(events, Event{Kind: "image_changed", Subject: ct.Name, Detail: ct.Image})
			case ct.RestartCount > prev.restarts || (prev.startedAt != "" && ct.StartedAt != prev.startedAt):
				events = append(events, Event{Kind: "restart", Subject: ct.Name, Detail: ct.Image})
			}
			if ct.OOMKilled && !prev.oom {
				events = append(events, Event{Kind: "oom_kill", Subject: ct.Name, Detail: "the container was stopped for using too much memory"})
			}
		}
		if ct.Status == "running" {
			u := readContainer(c.Sys.FS, ct.ID)
			row := Container{Name: ct.Name}
			if u.hasCPU {
				st.cpuUsec = u.cpuUsec
				if prev, ok := c.containers[ct.Name]; ok && prev.id == ct.ID && !first && secs > 0 && u.cpuUsec >= prev.cpuUsec {
					row.CPUPercent = pct(float64(u.cpuUsec-prev.cpuUsec) / 1e6 / secs / float64(cores) * 100)
				}
			}
			if u.hasMemory {
				mem := u.memBytes
				row.MemBytes = &mem
				if u.memLimit > 0 {
					limit := u.memLimit
					row.MemLimitBytes = &limit
				}
			}
			out = append(out, row)
		}
		seen[ct.Name] = st
	}
	c.containers = seen
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, events
}

// eventLine is how something that happened reads in the Logs screen.
func eventLine(now time.Time, e Event) LogLine {
	l := LogLine{At: now, Source: "docker", Kind: "event", Level: "info"}
	switch e.Kind {
	case "restart":
		l.Level, l.Text = "warn", "Container "+e.Subject+" restarted"
	case "image_changed":
		l.Text = "Container " + e.Subject + " now runs " + e.Detail
	case "oom_kill":
		l.Level = "error"
		if e.Subject == "" {
			l.Source, l.Text = "kernel", "Out of memory: "+e.Detail
		} else {
			l.Text = "Container " + e.Subject + ": " + e.Detail
		}
	default:
		l.Text = e.Kind + " " + e.Subject + " " + e.Detail
	}
	return l
}

// readAccessLogs adds the requests since the last minute, from the host's
// nginx log or from the output of web server containers. In agent mode it
// also keeps every container's output, and the host's web server logs, as
// log lines. The first minute only notes where each log ends, so nothing
// old is counted or sent.
func (c *Collector) readAccessLogs(ctx context.Context, now time.Time, list []system.Container, reqs *Requests) string {
	if c.fileOffset == nil {
		c.fileOffset, c.logSince = map[string]int64{}, map[string]time.Time{}
	}
	var sources []string
	for _, p := range AccessLogs {
		if c.tailFile(p, func(line string) {
			if r, ok := ParseAccessLine(line); ok {
				reqs.Add(r)
			}
			if c.Logs {
				c.buf.add(LogLine{At: now, Source: fileSource(p), Kind: "file", Text: line})
			}
		}) {
			sources = append(sources, "/"+p)
		}
	}
	if c.Logs {
		for _, p := range ErrorLogs {
			c.tailFile(p, func(line string) {
				c.buf.add(LogLine{At: now, Source: fileSource(p), Kind: "file", Text: line})
			})
		}
	}
	if c.Sys.Docker != nil {
		live := map[string]bool{}
		for _, ct := range list {
			live[ct.ID] = true
			web := webServerImage.MatchString(ct.Image)
			if ct.Status != "running" || (!web && !c.Logs) {
				continue
			}
			if web {
				sources = append(sources, ct.Name+" (container)")
			}
			since, ok := c.logSince[ct.ID]
			if !ok {
				// When the agent starts, nothing old is read. A container
				// that starts later, such as a deploy's, is read from its
				// start, so its first lines are not lost.
				started, err := time.Parse(time.RFC3339Nano, ct.StartedAt)
				if c.at.IsZero() || err != nil || now.Sub(started) > 10*time.Minute {
					c.logSince[ct.ID] = now
					continue
				}
				since = started.Add(-time.Second)
				c.logSince[ct.ID] = since
			}
			lines, err := c.Sys.Docker.Logs(ctx, ct.ID, since)
			if err != nil {
				continue
			}
			// Next time, start after the last line read, so none is counted twice.
			for _, l := range lines {
				if l.At.After(c.logSince[ct.ID]) {
					c.logSince[ct.ID] = l.At
				}
				if web {
					if r, ok := ParseAccessLine(l.Text); ok {
						reqs.Add(r)
					}
				}
				if c.Logs {
					c.buf.add(LogLine{At: l.At.UTC(), Source: ct.Name, Kind: "container", Text: l.Text})
				}
			}
		}
		// Forget containers that were removed.
		for id := range c.logSince {
			if !live[id] {
				delete(c.logSince, id)
			}
		}
	}
	return strings.Join(sources, ", ")
}

// tailFile reads what was added to a log file since last time, at most
// 8 MB a minute, and passes each whole line to each. A file that shrank
// was rotated, so it is read from the start.
func (c *Collector) tailFile(p string, each func(line string)) bool {
	f, err := c.Sys.FS.Open(p)
	if err != nil {
		delete(c.fileOffset, p)
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	size := info.Size()
	offset, seen := c.fileOffset[p]
	if !seen {
		c.fileOffset[p] = size
		return true
	}
	if size < offset {
		offset = 0
	}
	seeker, ok := f.(io.Seeker)
	if !ok {
		return true
	}
	if _, err := seeker.Seek(offset, io.SeekStart); err != nil {
		return true
	}
	data, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return true
	}
	// Leave a half-written last line for next time.
	if i := strings.LastIndexByte(string(data), '\n'); i >= 0 {
		data = data[:i+1]
	} else {
		data = nil
	}
	c.fileOffset[p] = offset + int64(len(data))
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			each(line)
		}
	}
	return true
}
