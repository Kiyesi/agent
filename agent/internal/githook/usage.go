package githook

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/pullcheck"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// Anonymous use counts, so Kiyesi knows how many people the hook helps and
// what it stops. An install is a random number made on this computer, not
// drawn from it, its owner or any repository. Kept with it: how many pushes
// were checked and stopped, how many findings of each rule, and the name
// and version of each malicious package stopped (public, known-bad names).
// Never a repository, branch, file, line or person. Sent at most once a day,
// waiting at most UsageTimeout; a failure is tried again the next day.
// KIYESI_NO_USAGE or DO_NOT_TRACK turns it off, as does kiyesi hook usage off.
const (
	UsageFile    = "usage.json"
	UsagePath    = "/v1/public/hook/usage"
	UsageEvery   = 24 * time.Hour
	UsageTimeout = 2 * time.Second
	// usageRetry is how long a report that did not go waits to be tried again.
	usageRetry = 24 * time.Hour
	// maxPackages caps the malicious packages kept between reports.
	maxPackages = 20
)

// usageTimeout is UsageTimeout; tests shorten it.
var usageTimeout = UsageTimeout

// Usage is the anonymous count kept in the cache folder.
type Usage struct {
	Dir    string
	API    string
	Client *http.Client
	Now    func() time.Time
	// Getenv reads the environment; tests replace it.
	Getenv func(string) string
}

// Counts are what one report says.
type Counts struct {
	Checked  int            `json:"checked"`
	Stopped  int            `json:"stopped"`
	Findings map[string]int `json:"findings"`
	Packages []Caught       `json:"packages"`
}

// Caught is a malicious package a push added, and how many pushes it stopped.
type Caught struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Count     int    `json:"count"`
}

// UsageReport is what is sent: nothing else.
type UsageReport struct {
	Report  string    `json:"report"`
	Install string    `json:"install"`
	Version string    `json:"version"`
	OS      string    `json:"os"`
	Arch    string    `json:"arch"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	Counts
}

// usageData is the file: the install, the counts since the last report, and
// a report made but not yet received, sent again as it was so it is stored
// once.
type usageData struct {
	Off     bool         `json:"off,omitempty"`
	Install string       `json:"install,omitempty"`
	Since   time.Time    `json:"since,omitzero"`
	SentAt  time.Time    `json:"sentAt,omitzero"`
	TriedAt time.Time    `json:"triedAt,omitzero"`
	Counts  Counts       `json:"counts"`
	Pending *UsageReport `json:"pending,omitempty"`
}

// UsageState is what kiyesi hook status says about counting.
type UsageState struct {
	On bool `json:"on"`
	// Why it is off: "KIYESI_NO_USAGE", "DO_NOT_TRACK" or "turned off".
	OffBy  string    `json:"offBy,omitempty"`
	SentAt time.Time `json:"sentAt,omitzero"`
}

func (u *Usage) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Usage) env(k string) string {
	if u.Getenv != nil {
		return u.Getenv(k)
	}
	return os.Getenv(k)
}

// set reads an on/off variable: anything but empty, 0 or false is on.
func set(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v != "" && v != "0" && v != "false"
}

func (u *Usage) path() string { return filepath.Join(u.Dir, UsageFile) }

func (u *Usage) load() usageData {
	var d usageData
	b, err := os.ReadFile(u.path()) // #nosec G304 -- Kiyesi's own cache file
	if err == nil {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

func (u *Usage) save(d usageData) {
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = writeAtomic(u.path(), b)
}

// State says whether counting is on, and why not.
func (u *Usage) State() UsageState {
	d := u.load()
	switch {
	case set(u.env("KIYESI_NO_USAGE")):
		return UsageState{OffBy: "KIYESI_NO_USAGE"}
	case set(u.env("DO_NOT_TRACK")):
		return UsageState{OffBy: "DO_NOT_TRACK"}
	case d.Off:
		return UsageState{OffBy: "turned off"}
	}
	return UsageState{On: true, SentAt: d.SentAt}
}

// SetOff turns counting off, forgetting the install and its counts, or on
// again with a new install.
func (u *Usage) SetOff(off bool) error {
	if off {
		b, _ := json.Marshal(usageData{Off: true})
		return writeAtomic(u.path(), b)
	}
	if err := os.Remove(u.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// newID is 16 random bytes in hex.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ready loads the file with an install, making one the first time. It says
// false when counting is off.
func (u *Usage) ready() (usageData, bool) {
	if !u.State().On {
		return usageData{}, false
	}
	d := u.load()
	if d.Install == "" {
		id, err := newID()
		if err != nil {
			return d, false
		}
		d = usageData{Install: id, Since: u.now()}
	}
	if d.Since.IsZero() {
		d.Since = u.now()
	}
	return d, true
}

// Count adds one checked push and what it found.
func (u *Usage) Count(rep Report) {
	d, ok := u.ready()
	if !ok {
		return
	}
	c := &d.Counts
	c.Checked++
	if rep.Stop {
		c.Stopped++
	}
	for _, f := range rep.Findings {
		if c.Findings == nil {
			c.Findings = map[string]int{}
		}
		c.Findings[f.Rule]++
		if f.Rule == pullcheck.RuleMalicious && f.Package != nil && Stops(f) {
			c.Packages = addCaught(c.Packages, *f.Package)
		}
	}
	u.save(d)
}

func addCaught(list []Caught, p pullcheck.Package) []Caught {
	for i := range list {
		if list[i].Ecosystem == p.Ecosystem && list[i].Name == p.Name && list[i].Version == p.Version {
			list[i].Count++
			return list
		}
	}
	if len(list) >= maxPackages {
		return list
	}
	return append(list, Caught{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Count: 1})
}

// Due says whether a report should be sent now: never sent, a day since the
// last, and a day since a try that failed.
func (u *Usage) Due() bool {
	d, ok := u.ready()
	if !ok {
		return false
	}
	now := u.now()
	if !d.TriedAt.IsZero() && now.Sub(d.TriedAt) < usageRetry && !now.Before(d.TriedAt) && d.TriedAt.After(d.SentAt) {
		return false
	}
	return d.SentAt.IsZero() || now.Sub(d.SentAt) >= UsageEvery || now.Before(d.SentAt)
}

// Send sends the counts when due (or always, with force), waiting at most
// UsageTimeout. A report that does not go is kept and sent again, the same,
// next time; counts made meanwhile wait for the report after.
func (u *Usage) Send(ctx context.Context, force bool) error {
	if !force && !u.Due() {
		return nil
	}
	d, ok := u.ready()
	if !ok {
		return nil
	}
	now := u.now()
	if d.Pending == nil {
		id, err := newID()
		if err != nil {
			return err
		}
		d.Pending = &UsageReport{
			Report: id, Install: d.Install, Version: version.Version,
			OS: runtime.GOOS, Arch: runtime.GOARCH,
			Since: d.Since, Until: now, Counts: d.Counts,
		}
		if d.Pending.Findings == nil {
			d.Pending.Findings = map[string]int{}
		}
		if d.Pending.Packages == nil {
			d.Pending.Packages = []Caught{}
		}
		d.Counts = Counts{}
		d.Since = now
	}
	d.TriedAt = now
	u.save(d)
	if err := u.post(ctx, *d.Pending); err != nil {
		return err
	}
	// Read again: a push may have counted while this was sent.
	after := u.load()
	after.Pending = nil
	after.SentAt = now
	u.save(after)
	return nil
}

func (u *Usage) post(ctx context.Context, r UsageReport) error {
	ctx, cancel := context.WithTimeout(ctx, usageTimeout)
	defer cancel()
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	url := strings.TrimRight(u.API, "/") + UsagePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "kiyesi-cli/"+version.Version)
	req.Header.Set("Content-Type", "application/json")
	c := u.Client
	if c == nil {
		c = &http.Client{}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Refused as it is (400): it would be refused again, so it is let go.
	if resp.StatusCode == http.StatusBadRequest {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the service answered %d", resp.StatusCode)
	}
	return nil
}
