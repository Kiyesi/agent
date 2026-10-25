// Package send delivers results to the service: batches with an id, masked,
// gzipped, over HTTPS, outgoing only. A batch that cannot be sent waits in
// an outbox on disk and is sent again later with the same id, so the
// service stores it once.
package send

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/collect"
	"github.com/kiyesi/kiyesi/agent/internal/dbwatch"
	"github.com/kiyesi/kiyesi/agent/internal/jobs"
	"github.com/kiyesi/kiyesi/agent/internal/keys"
	"github.com/kiyesi/kiyesi/agent/internal/machine"
	"github.com/kiyesi/kiyesi/agent/internal/mask"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/software"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// Batch is what the agent sends. Its shape matches the API's schema.
type Batch struct {
	BatchID      string `json:"batch_id"`
	SentAt       string `json:"sent_at"`
	AgentVersion string `json:"agent_version"`
	// MachineHash is a one-way hash of the server's machine ID, so the
	// service knows the same server connected twice. Left out when there
	// is no machine ID; the ID itself is never sent.
	MachineHash string `json:"machine_hash,omitempty"`
	Items       []Item `json:"items"`
}

// machineHash gives the hash for each batch, read once. Tests change it.
var machineHash = machine.Hash

// Item is a heartbeat, a scan, a minute of metrics, an event or a minute
// of log lines.
type Item struct {
	Kind    string           `json:"kind"`
	At      string           `json:"at"`
	Report  *scan.Report     `json:"report,omitempty"`
	Metrics *collect.Metrics `json:"metrics,omitempty"`
	Event   *collect.Event   `json:"event,omitempty"`
	Logs    *collect.Logs    `json:"logs,omitempty"`
	// A run of a timed job, recorded by kiyesi run.
	Job *jobs.Run `json:"job,omitempty"`
	// The timed jobs found in crontabs and systemd timers, with their next run.
	Jobs []jobs.Schedule `json:"jobs,omitempty"`
	// The databases in the settings: sizes and counts, never an address.
	Databases []dbwatch.Figures `json:"databases,omitempty"`
	// What is installed, for the service's advisories and tips.
	Software *software.List `json:"software,omitempty"`
	// A change sudo kiyesi fix made or undid, for the server's history.
	Fixed *Fixed `json:"fixed,omitempty"`
	// Who can sign in with an SSH key: fingerprints, never keys.
	Access *AccessList `json:"access,omitempty"`
}

// AccessList is every login key on the server, by account.
type AccessList struct {
	Keys []keys.Key `json:"keys"`
}

// Access makes the item for the login keys read this time.
func Access(at time.Time, ks []keys.Key) Item {
	if ks == nil {
		ks = []keys.Key{}
	}
	return Item{Kind: "access", At: at.UTC().Format(time.RFC3339), Access: &AccessList{Keys: ks}}
}

// Fixed is one change kiyesi fix made on this server, or undid.
type Fixed struct {
	ID   string `json:"id"`
	Fix  string `json:"fix"`
	Done string `json:"done"`
	// User is the person who ran sudo kiyesi fix.
	User string `json:"user"`
	Undo bool   `json:"undo,omitempty"`
}

// Software makes the item for what is installed.
func Software(at time.Time, l software.List) Item {
	return Item{Kind: "software", At: at.UTC().Format(time.RFC3339), Software: &l}
}

// Databases makes the item for the databases read this time.
func Databases(at time.Time, figures []dbwatch.Figures) []Item {
	if figures == nil {
		return nil
	}
	return []Item{{Kind: "databases", At: at.UTC().Format(time.RFC3339), Databases: figures}}
}

// Jobs makes the items for timed jobs: their runs, and, when found, their
// schedules. Their last lines of output are masked here, before they leave.
func Jobs(at time.Time, runs []jobs.Run, schedules []jobs.Schedule) []Item {
	stamp := at.UTC().Format(time.RFC3339)
	var out []Item
	for i := range runs {
		for j, l := range runs[i].LastLines {
			runs[i].LastLines[j] = mask.String(l)
		}
		out = append(out, Item{Kind: "job", At: stamp, Job: &runs[i]})
	}
	if schedules != nil {
		out = append(out, Item{Kind: "jobs", At: stamp, Jobs: schedules})
	}
	return out
}

// NewID returns a random version 4 UUID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Heartbeat makes a batch that says the server is alive.
func Heartbeat(at time.Time) Batch {
	stamp := at.UTC().Format(time.RFC3339)
	return Batch{BatchID: NewID(), SentAt: stamp, AgentVersion: version.Version, MachineHash: machineHash(), Items: []Item{{Kind: "heartbeat", At: stamp}}}
}

// Minute makes the batch sent each minute: a heartbeat, the minute's
// metrics, anything that happened, and the minute's log lines.
func Minute(at time.Time, m *collect.Metrics, events []collect.Event, logs *collect.Logs, extra ...Item) Batch {
	b := Heartbeat(at)
	stamp := b.SentAt
	if m != nil {
		b.Items = append(b.Items, Item{Kind: "metrics", At: stamp, Metrics: m})
	}
	for i := range events {
		b.Items = append(b.Items, Item{Kind: "event", At: stamp, Event: &events[i]})
	}
	if logs != nil && len(logs.Lines) > 0 {
		b.Items = append(b.Items, Item{Kind: "logs", At: stamp, Logs: logs})
	}
	b.Items = append(b.Items, extra...)
	return b
}

// Scan makes a batch holding one scan report.
func Scan(r scan.Report, now time.Time) Batch {
	r.ReportFile = "" // a path on this server is of no use to the service
	return Batch{
		BatchID: NewID(), SentAt: now.UTC().Format(time.RFC3339), AgentVersion: version.Version, MachineHash: machineHash(),
		Items: []Item{{Kind: "scan", At: r.StartedAt.UTC().Format(time.RFC3339), Report: &r}},
	}
}

// Items makes a batch of the given items, such as a key removal and the
// keys left after it.
func Items(now time.Time, items ...Item) Batch {
	return Batch{
		BatchID: NewID(), SentAt: now.UTC().Format(time.RFC3339), AgentVersion: version.Version, MachineHash: machineHash(),
		Items: items,
	}
}

// Fixes makes a batch with the scan after kiyesi fix, and what it changed.
func Fixes(r scan.Report, now time.Time, fixed []Fixed) Batch {
	b := Scan(r, now)
	stamp := now.UTC().Format(time.RFC3339)
	for i := range fixed {
		b.Items = append(b.Items, Item{Kind: "fixed", At: stamp, Fixed: &fixed[i]})
	}
	return b
}

// ErrNotAllowed means the token was refused: sending again will not help.
var ErrNotAllowed = errors.New("the service refused this server's token")

// ErrRejected means the service refused this batch for good, for example
// because it is too large. The batch is dropped.
var ErrRejected = errors.New("the service refused this batch")

// Client sends batches to one service address.
type Client struct {
	API   string // https://api.example.com
	Token string
	HTTP  *http.Client
	// OnHome hears the team's home country from each reply: a two-letter
	// code, or "" when the team has not chosen one. A service that does not
	// say leaves it unheard.
	OnHome func(code string)
	// OnPace hears how often the service asks this agent to report and
	// scan. A service that does not say, or says something out of bounds,
	// leaves it unheard.
	OnPace func(Pace)
}

// Pace is how often the service asks an agent to report and scan: less
// often on the free plan, which stores no figures or logs (Collect false).
// Scan 0 asks for no scans: a server the free plan does not watch.
type Pace struct {
	Beat    time.Duration
	Scan    time.Duration
	Collect bool
}

// CheckAPI refuses any address that is not HTTPS, apart from this machine,
// which is for local testing.
func CheckAPI(api string) error {
	u, err := url.Parse(api)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a web address: give one such as https://api.example.com", api)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return fmt.Errorf("%s must use https://. Only this machine (localhost) may use http://, for testing", api)
}

// noRedirect never follows a redirect: the service never sends one, and
// following it would hand the request's body, with what this server sent,
// to another address. The redirect comes back as the answer, which is an
// error to every caller.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// NewClient returns a client with a time limit on every request, that
// follows no redirect.
func NewClient(api, token string) *Client {
	return &Client{API: strings.TrimRight(api, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: noRedirect}}
}

func (c *Client) post(ctx context.Context, path string, body []byte, gzipped bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.API+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kiyesi-agent/"+version.Version)
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	return c.HTTP.Do(req)
}

// Connect tells the service this server is running and returns its id.
func (c *Client) Connect(ctx context.Context, hostname, os string) (string, error) {
	body, _ := json.Marshal(map[string]string{"hostname": hostname, "os": os, "agent_version": version.Version})
	resp, err := c.post(ctx, "/v1/agent/connect", body, false)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", c.API, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			ServerID string `json:"server_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ServerID == "" {
			return "", errors.New("the service answered in an unexpected form: update the agent")
		}
		return out.ServerID, nil
	case http.StatusUnauthorized, http.StatusNotFound:
		return "", ErrNotAllowed
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return "", fmt.Errorf("the service answered %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
}

// Encode masks a batch and gzips it. Masking happens here, the last step
// before anything leaves the server.
func Encode(b Batch) ([]byte, error) {
	mask.Value(&b)
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deliver sends one encoded batch. It returns nil when the service took it,
// ErrNotAllowed or ErrRejected when sending again cannot help, and any
// other error when it should be tried again later.
func (c *Client) deliver(ctx context.Context, body []byte) error {
	resp, err := c.post(ctx, "/v1/agent/batches", body, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK:
		c.hearHome(reply)
		c.hearPace(reply)
		return nil
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrNotAllowed
	case resp.StatusCode == http.StatusRequestEntityTooLarge, resp.StatusCode == http.StatusBadRequest:
		return ErrRejected
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusServiceUnavailable:
		return &BusyError{Status: resp.StatusCode, Wait: retryAfter(resp.Header.Get("Retry-After"))}
	default:
		return fmt.Errorf("the service answered %d", resp.StatusCode)
	}
}

// BusyError is the service asking for a pause: too many batches from this
// server in a minute (429), or catching up (503). Wait is how long it
// asked for, or 0 when it did not say.
type BusyError struct {
	Status int
	Wait   time.Duration
}

func (e *BusyError) Error() string { return fmt.Sprintf("the service answered %d", e.Status) }

// retryAfter reads a Retry-After of whole seconds, up to an hour.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(min(n, 3600)) * time.Second
}

// hearHome passes on the team's home country when the reply names it.
func (c *Client) hearHome(reply []byte) {
	if c.OnHome == nil {
		return
	}
	var r map[string]json.RawMessage
	if json.Unmarshal(reply, &r) != nil {
		return
	}
	raw, ok := r["home_country"]
	if !ok {
		return
	}
	var code *string
	if json.Unmarshal(raw, &code) != nil {
		return
	}
	switch {
	case code == nil:
		c.OnHome("")
	case len(*code) == 2 && strings.ToUpper(*code) == *code && strings.Trim(*code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "":
		c.OnHome(*code)
	}
}

// hearPace passes on the pace when the reply says one within bounds: a
// report every 30 seconds to 15 minutes, and a scan every 5 minutes to a
// day, or none.
func (c *Client) hearPace(reply []byte) {
	if c.OnPace == nil {
		return
	}
	var r struct {
		Pace *struct {
			Beat    int  `json:"beat_seconds"`
			Scan    int  `json:"scan_seconds"`
			Collect bool `json:"collect"`
		} `json:"pace"`
	}
	if json.Unmarshal(reply, &r) != nil || r.Pace == nil {
		return
	}
	p := r.Pace
	if p.Beat < 30 || p.Beat > 900 || (p.Scan != 0 && (p.Scan < 300 || p.Scan > 86400)) {
		return
	}
	c.OnPace(Pace{Beat: time.Duration(p.Beat) * time.Second, Scan: time.Duration(p.Scan) * time.Second, Collect: p.Collect})
}

// Outbox holds batches waiting to be sent, one file each, oldest first.
type Outbox struct {
	Dir      string
	MaxBytes int64
}

// Put writes a batch to the outbox, then drops the oldest batches if the
// outbox is over its size limit, so a long outage cannot fill the disk.
func (o Outbox) Put(b Batch, now time.Time) error {
	body, err := Encode(b)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s.json.gz", now.UnixNano(), b.BatchID)
	tmp := filepath.Join(o.Dir, "."+name)
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(o.Dir, name)); err != nil {
		return err
	}
	return o.trim()
}

func (o Outbox) files() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(o.Dir)
	if err != nil {
		return nil, err
	}
	var out []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json.gz") && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func (o Outbox) trim() error {
	files, err := o.files()
	if err != nil {
		return err
	}
	var total int64
	sizes := make([]int64, len(files))
	for i, f := range files {
		if info, err := f.Info(); err == nil {
			sizes[i] = info.Size()
			total += sizes[i]
		}
	}
	for i := 0; total > o.MaxBytes && i < len(files)-1; i++ {
		_ = os.Remove(filepath.Join(o.Dir, files[i].Name()))
		total -= sizes[i]
	}
	return nil
}

// Len returns how many batches are waiting.
func (o Outbox) Len() int {
	files, _ := o.files()
	return len(files)
}

// Flush sends waiting batches, oldest first, until one fails. A batch the
// service refuses for good is dropped, and reported through dropped; any
// other failure stops the flush and leaves the batch for next time.
func (o Outbox) Flush(ctx context.Context, c *Client) (sent int, err error) {
	return o.FlushReporting(ctx, c, nil)
}

// FlushReporting is Flush, calling dropped with each batch file the
// service refused for good.
func (o Outbox) FlushReporting(ctx context.Context, c *Client, dropped func(name string)) (sent int, err error) {
	return o.FlushUpTo(ctx, c, 0, dropped)
}

// FlushUpTo is FlushReporting sending at most max batches (0: all), so a
// backlog goes out at a pace the service takes.
func (o Outbox) FlushUpTo(ctx context.Context, c *Client, max int, dropped func(name string)) (sent int, err error) {
	files, err := o.files()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	if max > 0 && len(files) > max {
		files = files[:max]
	}
	for _, f := range files {
		path := filepath.Join(o.Dir, f.Name())
		body, err := os.ReadFile(path) // #nosec G304 -- a file listed from the agent's own outbox
		if err != nil {
			continue
		}
		switch err := c.deliver(ctx, body); {
		case err == nil, errors.Is(err, ErrRejected):
			_ = os.Remove(path)
			if err == nil {
				sent++
			} else if dropped != nil {
				dropped(f.Name())
			}
		default:
			return sent, err
		}
	}
	return sent, nil
}

// Backoff returns the wait before attempt n (from 0): growing, randomised,
// and never over max, so many servers coming back do not all call at once.
func Backoff(n int, base, max time.Duration) time.Duration {
	d := base << min(n, 16)
	if d <= 0 || d > max {
		d = max
	}
	j, _ := rand.Int(rand.Reader, big.NewInt(int64(d/2)+1))
	return d/2 + time.Duration(j.Int64())
}
