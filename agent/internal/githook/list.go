package githook

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// The malicious-package list is the service's own (GET
// /v1/public/malicious-packages, no account needed), kept in the cache
// folder and asked for again when the copy is over RefreshAfter old.
const (
	ListFile     = "malicious-packages.jsonl"
	listMeta     = "malicious-packages.json"
	ListPath     = "/v1/public/malicious-packages"
	RefreshAfter = 6 * time.Hour
	// FetchTimeout is the longest a push waits for the list.
	FetchTimeout = 3 * time.Second
	// RetryAfter is how long a failed refresh waits before the next try,
	// so a push without the internet does not wait 3 seconds every time.
	RetryAfter = 30 * time.Minute
	// maxList caps the list once uncompressed, and as sent.
	maxList = 64 << 20
)

// fetchTimeout is FetchTimeout; tests shorten it.
var fetchTimeout = FetchTimeout

// List is the cached copy of the malicious-package list.
type List struct {
	// Dir is the cache folder, such as ~/Library/Caches/kiyesi.
	Dir string
	// API is the service's address, such as https://api.kiyesi.dev.
	API    string
	Client *http.Client
	Now    func() time.Time
}

// listMetaData is what is kept beside the list.
type listMetaData struct {
	ETag string `json:"etag,omitempty"`
	// CheckedAt is when the service last gave the list or said it had not changed.
	CheckedAt time.Time `json:"checkedAt"`
	// TriedAt is the last try, failed or not.
	TriedAt time.Time `json:"triedAt"`
}

// ListState is the copy this machine has, and what the last refresh did.
type ListState struct {
	Path string `json:"path"`
	// Present is false when there is no copy: the malicious rule cannot run.
	Present bool `json:"present"`
	// FetchedAt is when the service last read the list from its sources:
	// how old the list itself is.
	FetchedAt time.Time `json:"fetchedAt,omitzero"`
	// CheckedAt is when this machine last got the list or heard it was current.
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	// Refreshed is true when this run got a new list or heard it was current.
	Refreshed bool `json:"refreshed"`
	// Failed says why a refresh due now did not work, or "".
	Failed string `json:"failed,omitempty"`
}

func (l *List) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Path is the list file Check reads.
func (l *List) Path() string { return filepath.Join(l.Dir, ListFile) }

// State reads the copy's head and what was kept beside it, without asking
// the service.
func (l *List) State() ListState {
	st := ListState{Path: l.Path()}
	m := l.meta()
	st.CheckedAt = m.CheckedAt
	if at, ok := readHead(st.Path); ok {
		st.Present = true
		st.FetchedAt = at
	}
	return st
}

func (l *List) meta() listMetaData {
	var m listMetaData
	b, err := os.ReadFile(filepath.Join(l.Dir, listMeta)) // #nosec G304 -- Kiyesi's own cache file
	if err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (l *List) saveMeta(m listMetaData) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	_ = writeAtomic(filepath.Join(l.Dir, listMeta), b)
}

// Refresh asks the service for the list when the copy is over RefreshAfter
// old, or always when force is set, waiting at most FetchTimeout. A failure
// leaves the copy as it was and is said in Failed.
func (l *List) Refresh(ctx context.Context, force bool) ListState {
	st := l.State()
	m := l.meta()
	now := l.now()
	if !force {
		fresh := st.Present && now.Sub(m.CheckedAt) < RefreshAfter && !now.Before(m.CheckedAt)
		waiting := now.Sub(m.TriedAt) < RetryAfter && !now.Before(m.TriedAt) && m.TriedAt.After(m.CheckedAt)
		if fresh {
			return st
		}
		if waiting {
			st.Failed = "the last try, " + Ago(now.Sub(m.TriedAt)) + " ago, did not work"
			return st
		}
	}
	m.TriedAt = now
	etag, err := l.fetch(ctx, st.Present, m.ETag)
	if err != nil {
		l.saveMeta(m)
		st.Failed = err.Error()
		return st
	}
	if etag != "" {
		m.ETag = etag
	}
	m.CheckedAt = now
	l.saveMeta(m)
	out := l.State()
	out.Refreshed = true
	return out
}

// fetch gets the list, or hears it has not changed (304). It returns the
// new version tag.
func (l *List) fetch(ctx context.Context, have bool, etag string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	url := strings.TrimRight(l.API, "/") + ListPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "kiyesi-cli/"+version.Version)
	req.Header.Set("Accept", "application/x-ndjson")
	// Set by hand, so Go does not unpack it by itself: it is unpacked
	// below, with a size cap.
	req.Header.Set("Accept-Encoding", "gzip")
	if have && etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	c := l.Client
	if c == nil {
		c = &http.Client{}
	}
	resp, err := c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("no answer within %d seconds", int(fetchTimeout/time.Second))
		}
		return "", errors.New("could not reach " + req.URL.Host)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && have {
		return etag, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the service answered %d", resp.StatusCode)
	}
	body := bufio.NewReader(io.LimitReader(resp.Body, maxList+1))
	var r io.Reader = body
	magic, _ := body.Peek(2)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") || bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return "", errors.New("the list was not sent whole")
		}
		defer zr.Close()
		r = zr
	}
	data, err := io.ReadAll(io.LimitReader(r, maxList+1))
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("no answer within %d seconds", int(fetchTimeout/time.Second))
		}
		return "", errors.New("the list was not sent whole")
	}
	if len(data) > maxList {
		return "", errors.New("the list is over 64 MB")
	}
	if _, ok := headOf(data); !ok {
		return "", errors.New("the service sent something that is not the list")
	}
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return "", fmt.Errorf("could not keep the list: %w", err)
	}
	if err := writeAtomic(l.Path(), data); err != nil {
		return "", fmt.Errorf("could not keep the list: %w", err)
	}
	return resp.Header.Get("ETag"), nil
}

// headOf reads the list's first line: {"sha","fetchedAt"}.
func headOf(data []byte) (time.Time, bool) {
	first, _, _ := bytes.Cut(data, []byte("\n"))
	var h struct {
		FetchedAt string `json:"fetchedAt"`
	}
	if json.Unmarshal(bytes.TrimRight(first, "\r"), &h) != nil || h.FetchedAt == "" {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, h.FetchedAt)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

func readHead(path string) (time.Time, bool) {
	f, err := os.Open(path) // #nosec G304 -- Kiyesi's own cache file
	if err != nil {
		return time.Time{}, false
	}
	defer f.Close()
	line, _ := bufio.NewReader(io.LimitReader(f, 4096)).ReadBytes('\n')
	return headOf(line)
}

// writeAtomic replaces path with data in one step.
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // #nosec G104 -- gone already after the rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Ago says a span of time in a few words: 5 minutes, 3 hours, 2 days.
func Ago(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/(24*time.Hour)), "day")
	}
}
