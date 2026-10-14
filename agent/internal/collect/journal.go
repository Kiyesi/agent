package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// The system log (journald), read with journalctl (decisions log,
// 2026-10-10):
//
//   - the services you run yourself (unit files in /etc/systemd/system,
//     such as myapp.service or pm2-root.service) and cron: every line;
//   - every other service and the kernel: warnings and errors only;
//   - SSH, sudo and sign-in records: never, unless Auth is set, because
//     they hold usernames, addresses and typed commands;
//   - lines from containers: never here, because the Docker logs API
//     already sends them.

// JournalRules are the settings for the system log.
type JournalRules struct {
	On bool
	// Auth also sends SSH, sudo and sign-in records.
	Auth bool
	// Firewall also sends the firewall's blocked-connection lines, which on
	// a server open to the internet are mostly scans.
	Firewall bool
	// Include sends every line of these units, beyond your own services.
	Include []string
}

// journalFields are the only fields asked for, so the output stays small.
const journalFields = "MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT,SYSLOG_FACILITY,CONTAINER_ID,__REALTIME_TIMESTAMP"

// journalMax is the most entries read from each query in one minute.
const journalMax = "3000"

// Services that record sign-ins and commands people type.
var authUnits = map[string]bool{
	"ssh.service": true, "sshd.service": true, "systemd-logind.service": true,
}
var authIdentifiers = map[string]bool{
	"sshd": true, "sudo": true, "su": true, "login": true, "systemd-logind": true,
	"polkitd": true, "passwd": true, "chpasswd": true, "useradd": true, "usermod": true,
}

// firewallLine is a blocked or logged connection from ufw, firewalld or an iptables LOG rule.
var firewallLine = regexp.MustCompile(`^\[(UFW (BLOCK|AUDIT|ALLOW|LIMIT BLOCK)|UFW BLOCK|FINAL_REJECT|FINAL_DROP|IPTABLES[^\]]*)\]|^(filter_|nft[_ ])\w*(DROP|REJECT)`)

// journal keeps where each query read up to, in microseconds since 1970.
type journal struct {
	all, own int64
}

// ownUnits are the services the server's people installed: unit files
// written into /etc/systemd/system, not links to the system's own.
func ownUnits(fsys fs.FS, include []string) []string {
	units := map[string]bool{"cron.service": true}
	if entries, err := fs.ReadDir(fsys, "etc/systemd/system"); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".service") {
				units[e.Name()] = true
			}
		}
	}
	for _, u := range include {
		if u = strings.TrimSpace(u); u != "" {
			if !strings.Contains(u, ".") {
				u += ".service"
			}
			units[u] = true
		}
	}
	out := make([]string, 0, len(units))
	for u := range units {
		out = append(out, u)
	}
	return out
}

// readJournal adds the system log's new lines to b. The first minute only
// notes the time, so nothing old is sent.
func (j *journal) read(ctx context.Context, sys *system.System, rules JournalRules, now time.Time, b *logBuffer) {
	if !rules.On || sys.Exec == nil || !sys.Exec.Has("journalctl") {
		return
	}
	if j.all == 0 {
		j.all, j.own = now.UnixMicro(), now.UnixMicro()
		return
	}
	seen := map[string]bool{}
	// Warnings and errors from everything.
	j.all = j.query(ctx, sys, j.all, []string{"--priority=warning"}, rules, seen, b)
	// Every line from your own services.
	var units []string
	for _, u := range ownUnits(sys.FS, rules.Include) {
		units = append(units, "--unit="+u)
	}
	j.own = j.query(ctx, sys, j.own, units, rules, seen, b)
}

func (j *journal) query(ctx context.Context, sys *system.System, after int64, filter []string, rules JournalRules, seen map[string]bool, b *logBuffer) int64 {
	args := []string{
		"--output=json", "--no-pager", "--quiet", "--lines=" + journalMax,
		"--output-fields=" + journalFields,
		"--since=@" + strconv.FormatInt(after/1_000_000, 10),
	}
	args = append(args, filter...)
	out, err := sys.Exec.Run(ctx, "journalctl", args...)
	if err != nil && len(out) == 0 {
		return after
	}
	newest := after
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e struct {
			Message    any    `json:"MESSAGE"`
			Priority   string `json:"PRIORITY"`
			Unit       string `json:"_SYSTEMD_UNIT"`
			Identifier string `json:"SYSLOG_IDENTIFIER"`
			Transport  string `json:"_TRANSPORT"`
			Facility   string `json:"SYSLOG_FACILITY"`
			Container  string `json:"CONTAINER_ID"`
			Realtime   string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		usec, err := strconv.ParseInt(e.Realtime, 10, 64)
		if err != nil || usec <= after {
			continue
		}
		newest = max(newest, usec)
		// Both queries can return the same line: a warning from your own service.
		key := e.Realtime + e.Unit + e.Identifier
		msg, ok := e.Message.(string)
		if !ok || seen[key+msg] || e.Container != "" {
			continue
		}
		seen[key+msg] = true
		if !rules.Firewall && e.Transport == "kernel" && firewallLine.MatchString(msg) {
			continue
		}
		facility, _ := strconv.Atoi(e.Facility)
		if !rules.Auth && (authUnits[e.Unit] || authIdentifiers[e.Identifier] || facility == 4 || facility == 10) {
			continue
		}
		source := strings.TrimSuffix(e.Unit, ".service")
		switch {
		case e.Transport == "kernel":
			source = "kernel"
		case source == "" || strings.HasPrefix(source, "session-") || strings.HasPrefix(source, "user@"):
			source = e.Identifier
		}
		if source == "" {
			source = "system"
		}
		p, err := strconv.Atoi(e.Priority)
		if err != nil {
			p = 6
		}
		b.add(LogLine{At: time.UnixMicro(usec).UTC(), Source: source, Kind: "journal", Level: priorityLevel(p), Text: msg})
	}
	return newest
}
