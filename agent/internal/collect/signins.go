package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// The sign-in watch (decisions log, 2026-10-16): each minute, SSH's own
// "Accepted" lines from the system log, and a note only for a sign-in not
// seen before on this server: a user from an address it has not used. The
// note holds the user, the address and how they signed in, nothing more;
// the rest of the sign-in records stay on the server, as they always have.
// What was seen is kept in a small file, so a restart repeats nothing.

// accepted is OpenSSH's line for a sign-in that worked.
var accepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)

// seenMax is how many user and address pairs are remembered; the least
// recently used are forgotten first.
const seenMax = 2000

// SigninWatch reads new SSH sign-ins.
type SigninWatch struct {
	// Path is the file that remembers the pairs already seen.
	Path  string
	since int64 // microseconds since 1970, read up to
	seen  map[string]time.Time
}

// Read returns a "signin" event for each user and address pair not seen
// before. The first minute only notes the time, so nothing old is sent.
func (w *SigninWatch) Read(ctx context.Context, sys *system.System, now time.Time) []Event {
	if sys.Exec == nil || !sys.Exec.Has("journalctl") {
		return nil
	}
	if w.seen == nil {
		w.seen = w.load()
	}
	if w.since == 0 {
		w.since = now.UnixMicro()
		return nil
	}
	// sshd-session writes these lines from OpenSSH 9.8 (Debian 13, Ubuntu 25.04).
	out, err := sys.Exec.Run(ctx, "journalctl", "--output=json", "--no-pager", "--quiet", "--lines="+journalMax,
		"--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
		"--since=@"+strconv.FormatInt(w.since/1_000_000, 10),
		"--identifier=sshd", "--identifier=sshd-session")
	if err != nil && len(out) == 0 {
		return nil
	}
	var events []Event
	changed := false
	sc := bufio.NewScanner(bytes.NewReader(out))
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
		if err != nil || usec <= w.since {
			continue
		}
		w.since = max(w.since, usec)
		msg, _ := e.Message.(string)
		m := accepted.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		method, user, address := m[1], m[2], m[3]
		ip, err := netip.ParseAddr(address)
		if err != nil || len(user) > 64 {
			continue
		}
		address = ip.Unmap().String()
		at := time.UnixMicro(usec).UTC()
		key := user + "@" + address
		_, known := w.seen[key]
		w.seen[key] = at
		changed = true
		if known {
			continue
		}
		events = append(events, Event{Kind: "signin", Subject: user, Detail: method, Address: address, At: at.Format(time.RFC3339)})
	}
	if changed {
		w.save()
	}
	return events
}

func (w *SigninWatch) load() map[string]time.Time {
	m := map[string]time.Time{}
	if w.Path == "" {
		return m
	}
	data, err := os.ReadFile(w.Path)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(data, &m)
	return m
}

// save keeps the most recent pairs, readable by root only.
func (w *SigninWatch) save() {
	if w.Path == "" {
		return
	}
	if len(w.seen) > seenMax {
		keys := make([]string, 0, len(w.seen))
		for k := range w.seen {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return w.seen[keys[i]].After(w.seen[keys[j]]) })
		for _, k := range keys[seenMax:] {
			delete(w.seen, k)
		}
	}
	data, err := json.Marshal(w.seen)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(w.Path), 0o700)
	tmp := w.Path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, w.Path)
	}
}

// Private reports whether an address is on a private or local network,
// where a country means nothing.
func Private(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err != nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || strings.HasPrefix(address, "100.64.")
}
