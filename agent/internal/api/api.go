// Package api is the client the laptop commands use: sign in through the
// device flow, then read servers and their latest report as that person.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// ClientID is how the service knows the device flow comes from this CLI.
const ClientID = "kiyesi-cli"

var (
	// ErrSignedOut means the token is missing, expired or revoked.
	ErrSignedOut = errors.New("you are signed out: run kiyesi login")
	// ErrNotFound means the thing does not exist, or the person may not see it.
	ErrNotFound = errors.New("not found")
	// ErrPending means the person has not approved the sign-in yet.
	ErrPending = errors.New("waiting for approval")
	// ErrSlowDown means poll less often.
	ErrSlowDown = errors.New("slow down")
	// ErrDenied means the person said no in the browser.
	ErrDenied = errors.New("the sign-in was refused in the browser")
	// ErrExpired means the code ran out of time.
	ErrExpired = errors.New("the code expired: run kiyesi login again")
)

// Problem is an answer the service gave, in its own words.
type Problem struct {
	Status  int
	Code    string
	Message string
}

func (p *Problem) Error() string {
	if p.Message != "" {
		return p.Message
	}
	return fmt.Sprintf("the service answered %d", p.Status)
}

// Client talks to the API as a signed-in person.
type Client struct {
	API   string
	Token string
	// TeamID is which of the person's teams requests are for; empty for their oldest.
	TeamID string
	// Project and Env narrow any list (--project, --env); empty for all.
	Project string
	Env     string
	HTTP    *http.Client
}

// New returns a client with a time limit on every request.
func New(api, token string) *Client {
	return &Client{API: strings.TrimRight(api, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	data, err := c.send(ctx, method, path, in)
	if err != nil {
		return err
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("the service answered in an unexpected form: update kiyesi")
	}
	return nil
}

// send makes one request and returns the body of a good answer, or the
// service's problem in its own words.
func (c *Client) send(ctx context.Context, method, path string, in any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.API+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.TeamID != "" {
		req.Header.Set("X-Kiyesi-Team", c.TeamID)
	}
	if method == http.MethodGet && c.Project != "" {
		req.Header.Set("X-Kiyesi-Project", c.Project)
	}
	if method == http.MethodGet && c.Env != "" {
		req.Header.Set("X-Kiyesi-Env", c.Env)
	}
	req.Header.Set("User-Agent", "kiyesi-cli/"+version.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", c.API, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		var p struct {
			Error       string `json:"error"`
			Message     string `json:"message"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(data, &p)
		switch {
		case resp.StatusCode == http.StatusUnauthorized && p.Error != "authorization_pending":
			return nil, ErrSignedOut
		case resp.StatusCode == http.StatusNotFound:
			return nil, &NotFoundError{Message: p.Message}
		}
		msg := p.Message
		if msg == "" {
			msg = p.Description
		}
		return nil, &Problem{Status: resp.StatusCode, Code: p.Error, Message: msg}
	}
	return data, nil
}

// DeviceCode is the start of a sign-in: a code to type in the browser.
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartLogin asks for a code to approve in the browser.
func (c *Client) StartLogin(ctx context.Context) (DeviceCode, error) {
	var d DeviceCode
	err := c.do(ctx, http.MethodPost, "/api/auth/device/code", map[string]string{"client_id": ClientID}, &d)
	return d, err
}

// PollLogin asks once whether the code was approved, and returns the token
// when it was.
func (c *Client) PollLogin(ctx context.Context, deviceCode string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	err := c.do(ctx, http.MethodPost, "/api/auth/device/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode,
		"client_id":   ClientID,
	}, &out)
	var p *Problem
	if errors.As(err, &p) {
		switch p.Code {
		case "authorization_pending":
			return "", ErrPending
		case "slow_down":
			return "", ErrSlowDown
		case "access_denied":
			return "", ErrDenied
		case "expired_token":
			return "", ErrExpired
		}
	}
	if errors.Is(err, ErrSignedOut) {
		return "", ErrPending
	}
	if err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("the service answered in an unexpected form: update kiyesi")
	}
	return out.AccessToken, nil
}

// Logout ends the session on the service.
func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/auth/sign-out", map[string]string{}, nil)
}

// Me is who is signed in.
type Me struct {
	User struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"user"`
	Team struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"team"`
	Role     string `json:"role"`
	RoleName string `json:"roleName"`
	// Teams is every team the person is in.
	Teams []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		RoleName string `json:"roleName"`
	} `json:"teams"`
}

// Me returns who is signed in.
func (c *Client) Me(ctx context.Context) (Me, error) {
	var m Me
	err := c.do(ctx, http.MethodGet, "/v1/me", nil, &m)
	return m, err
}

// Summary is the short form of a scan, kept with each server.
type Summary struct {
	At    time.Time `json:"at"`
	Grade struct {
		Score   int    `json:"score"`
		Letter  string `json:"letter"`
		BasedOn int    `json:"basedOn"`
		Total   int    `json:"total"`
	} `json:"grade"`
	Counts struct {
		Critical int `json:"critical"`
		Warnings int `json:"warnings"`
		Passed   int `json:"passed"`
		Skipped  int `json:"skipped"`
	} `json:"counts"`
	Location *struct {
		Place      string `json:"place"`
		Country    string `json:"country"`
		Confidence string `json:"confidence"`
	} `json:"location"`
}

// Server is one row of the servers list.
type Server struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Project *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
	Environment  string     `json:"environment"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	AgentVersion string     `json:"agentVersion"`
	Connected    bool       `json:"connected"`
	State        string     `json:"state"`
	LastSeenAt   *time.Time `json:"lastSeenAt"`
	Silent       bool       `json:"silent"`
	LastScan     *Summary   `json:"lastScan"`
	// The calm streak: whole days since a scan last found something critical.
	Calm *struct {
		Days int `json:"days"`
	} `json:"calm"`
	LastMetrics *struct {
		CPU    *float64 `json:"cpu"`
		Memory *float64 `json:"memory"`
		Disk   *float64 `json:"disk"`
	} `json:"lastMetrics"`
}

// Servers lists the servers the person may see, worst first.
func (c *Client) Servers(ctx context.Context) ([]Server, error) {
	var out struct {
		Servers []Server `json:"servers"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/servers", nil, &out)
	return out.Servers, err
}

// DisconnectServer stops a server's token; its history stays until it expires.
func (c *Client) DisconnectServer(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/servers/"+url.PathEscape(id)+"/disconnect", nil, nil)
}

// DeleteServer hides a server at once and erases it after the grace
// period. name must be the server's name again, and code a fresh
// two-step code. It returns when the server is erased for good.
func (c *Client) DeleteServer(ctx context.Context, id, name, code string) (time.Time, error) {
	var out struct {
		PurgeAt time.Time `json:"purgeAt"`
	}
	err := c.do(ctx, http.MethodDelete, "/v1/servers/"+url.PathEscape(id), map[string]string{"name": name, "twoStepCode": code}, &out)
	return out.PurgeAt, err
}

// DeletedServer is a server that can still be restored.
type DeletedServer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	DeletedAt time.Time `json:"deletedAt"`
	PurgeAt   time.Time `json:"purgeAt"`
}

// DeletedServers lists the servers that can still be restored.
func (c *Client) DeletedServers(ctx context.Context) ([]DeletedServer, error) {
	var out struct {
		Servers []DeletedServer `json:"servers"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/servers/deleted", nil, &out)
	return out.Servers, err
}

// RestoreServer brings a deleted server back, disconnected.
func (c *Client) RestoreServer(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/servers/"+url.PathEscape(id)+"/restore", nil, nil)
}

// NewServerToken makes a new token for a server and returns the command
// to run on it; the old tokens stop working.
func (c *Client) NewServerToken(ctx context.Context, id, code string) (string, error) {
	var out struct {
		Command string `json:"command"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/servers/"+url.PathEscape(id)+"/token", map[string]string{"twoStepCode": code}, &out)
	return out.Command, err
}

// Detail is one server and its latest full report.
type Detail struct {
	Server   Server       `json:"server"`
	Report   *scan.Report `json:"report"`
	ReportAt *time.Time   `json:"reportAt"`
}

// Server returns one server and its latest full report.
func (c *Client) Server(ctx context.Context, id string) (Detail, error) {
	var d Detail
	err := c.do(ctx, http.MethodGet, "/v1/servers/"+id, nil, &d)
	return d, err
}

// Channel is a place alerts go: a Telegram chat, a Slack channel or an email address.
type Channel struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Linked bool   `json:"linked"`
	Detail string `json:"detail"`
}

// Channels lists the team's alert channels.
func (c *Client) Channels(ctx context.Context) ([]Channel, error) {
	var out struct {
		Channels []Channel `json:"channels"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/alerts/channels", nil, &out)
	return out.Channels, err
}

// TestChannel sends a test message to one channel.
func (c *Client) TestChannel(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/alerts/channels/"+id+"/test", map[string]string{}, nil)
}

// Alert is one open problem.
type Alert struct {
	ID       string     `json:"id"`
	Kind     string     `json:"kind"`
	Subject  string     `json:"subject"`
	Sentence string     `json:"sentence"`
	OpenedAt time.Time  `json:"openedAt"`
	AckedAt  *time.Time `json:"ackedAt"`
}

// OpenAlerts lists the open alerts the person can see.
func (c *Client) OpenAlerts(ctx context.Context) ([]Alert, error) {
	var out struct {
		Alerts []Alert `json:"alerts"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/alerts?open=1", nil, &out)
	return out.Alerts, err
}

// Mute silences a server's alerts for a time such as 30m, 2h or 1d.
func (c *Client) Mute(ctx context.Context, serverID, duration string) (time.Time, error) {
	var out struct {
		Until time.Time `json:"until"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/servers/"+serverID+"/mute", map[string]string{"for": duration}, &out)
	return out.Until, err
}

// Unmute ends a mute early.
func (c *Client) Unmute(ctx context.Context, serverID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/servers/"+serverID+"/mute", nil, nil)
}

// UptimeCheck is one address checked from outside.
type UptimeCheck struct {
	ID        string  `json:"id"`
	ProjectID *string `json:"projectId"`
	Name      string  `json:"name"`
	URL       string  `json:"url"`
	Status    string  `json:"status"`
	Last      *struct {
		At     time.Time `json:"at"`
		OK     bool      `json:"ok"`
		Status *int      `json:"status"`
		MS     *int      `json:"ms"`
		Error  *string   `json:"error"`
	} `json:"last"`
}

// Uptime lists the uptime checks.
func (c *Client) Uptime(ctx context.Context) ([]UptimeCheck, error) {
	var out struct {
		Checks []UptimeCheck `json:"checks"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/uptime", nil, &out)
	return out.Checks, err
}

// AddUptime adds an address to check.
func (c *Client) AddUptime(ctx context.Context, url, name string) (string, error) {
	body := map[string]string{"url": url}
	if name != "" {
		body["name"] = name
	}
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/uptime", body, &out)
	return out.ID, err
}

// Event is one line of History.
type Event struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Kind       string    `json:"kind"`
	Title      string    `json:"title"`
	ServerName *string   `json:"serverName"`
	App        *string   `json:"app"`
	Version    *string   `json:"version"`
	By         *string   `json:"by"`
}

// History lists what happened, newest first. since is 1h, 24h, 7d, 30d or 90d.
func (c *Client) History(ctx context.Context, since, serverID, kinds string) ([]Event, error) {
	q := url.Values{"since": {since}}
	if serverID != "" {
		q.Set("server", serverID)
	}
	if kinds != "" {
		q.Set("kind", kinds)
	}
	var out struct {
		Events []Event `json:"events"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/history?"+q.Encode(), nil, &out)
	return out.Events, err
}

// LogQuery picks log lines. Range is 15m, 1h, 6h, 24h or 7d; Level is
// "", "error" or "warn" (warnings and errors). Since asks for Follow: the
// lines from a little before it.
type LogQuery struct {
	ServerID, Source, Level, Search, Range string
	Since                                  time.Time
	Limit                                  int
}

// LogLine is one line from a server.
type LogLine struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Server     string    `json:"server"`
	ServerName string    `json:"serverName"`
	Source     string    `json:"source"`
	Kind       string    `json:"kind"`
	Level      string    `json:"level"`
	Text       string    `json:"text"`
}

// LogPage is the lines that matched, oldest first.
type LogPage struct {
	Lines  []LogLine `json:"lines"`
	More   bool      `json:"more"`
	Notice *string   `json:"notice"`
}

// Logs searches log lines.
func (c *Client) Logs(ctx context.Context, q LogQuery) (LogPage, error) {
	v := q.values()
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339Nano))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	var out LogPage
	err := c.do(ctx, http.MethodGet, "/v1/logs?"+v.Encode(), nil, &out)
	return out, err
}

// ExportLogs writes every line that matches, oldest first, to w, as "txt"
// or "jsonl". It can take minutes, so only ctx limits it.
func (c *Client) ExportLogs(ctx context.Context, q LogQuery, format string, w io.Writer) error {
	v := q.values()
	v.Set("format", format)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.API+"/v1/logs/export?"+v.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "kiyesi-cli/"+version.Version)
	long := *c.HTTP
	long.Timeout = 0
	resp, err := long.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.API, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var p struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &p)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return ErrSignedOut
		case http.StatusNotFound:
			return ErrNotFound
		}
		return &Problem{Status: resp.StatusCode, Code: p.Error, Message: p.Message}
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (q LogQuery) values() url.Values {
	v := url.Values{}
	for k, val := range map[string]string{"server": q.ServerID, "source": q.Source, "level": q.Level, "q": q.Search, "range": q.Range} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v
}

// ErrorGroup is one kind of browser error.
type ErrorGroup struct {
	ID       string `json:"id"`
	Frontend struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"frontend"`
	Kind      string `json:"kind"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Where     string `json:"where"`
	Mapped    bool   `json:"mapped"`
	Events    int    `json:"events"`
	Users     *int   `json:"users"`
	FirstSeen struct {
		At      time.Time `json:"at"`
		Version string    `json:"version"`
	} `json:"firstSeen"`
	LastSeen struct {
		At      time.Time `json:"at"`
		Version string    `json:"version"`
	} `json:"lastSeen"`
}

// BrowserErrors is the Browser errors screen: today's figures and the groups, busiest first.
type BrowserErrors struct {
	Today struct {
		Errors    int      `json:"errors"`
		Groups    int      `json:"groups"`
		Frontends []string `json:"frontends"`
	} `json:"today"`
	Groups []ErrorGroup `json:"groups"`
}

// Frontend is a site that reports browser errors.
type Frontend struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Sites []string `json:"sites"`
}

// Frontends lists the frontends the person can see.
func (c *Client) Frontends(ctx context.Context) ([]Frontend, error) {
	var out struct {
		Frontends []Frontend `json:"frontends"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/frontends", nil, &out)
	return out.Frontends, err
}

// Errors lists browser errors in a range (24h, 7d or 30d), optionally for one frontend.
func (c *Client) Errors(ctx context.Context, frontendID, rng string) (BrowserErrors, error) {
	v := url.Values{"range": {rng}}
	if frontendID != "" {
		v.Set("frontend", frontendID)
	}
	var out BrowserErrors
	err := c.do(ctx, http.MethodGet, "/v1/browser/errors?"+v.Encode(), nil, &out)
	return out, err
}

// UploadSourcemap sends one gzipped source map from a build.
func (c *Client) UploadSourcemap(ctx context.Context, frontend, appVersion, path string, gz []byte) error {
	v := url.Values{"frontend": {frontend}, "version": {appVersion}, "path": {path}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.API+"/v1/sourcemaps?"+v.Encode(), bytes.NewReader(gz))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "kiyesi-cli/"+version.Version)
	long := *c.HTTP
	long.Timeout = 2 * time.Minute
	resp, err := long.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.API, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var p struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &p)
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrSignedOut
		}
		return &Problem{Status: resp.StatusCode, Code: p.Error, Message: p.Message}
	}
	return nil
}

// Deploy is a deploy marker to record.
type Deploy struct {
	App         string `json:"app"`
	Version     string `json:"version"`
	By          string `json:"by,omitempty"`
	Server      string `json:"server,omitempty"`
	Project     string `json:"project,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// MarkDeploy records a deploy.
func (c *Client) MarkDeploy(ctx context.Context, d Deploy) error {
	return c.do(ctx, http.MethodPost, "/v1/deploys", d, nil)
}

// Charts is a server's metrics over a time range.
type Charts struct {
	Step       int                     `json:"step"`
	CPU        [][2]float64            `json:"cpu"`
	Memory     [][2]float64            `json:"memory"`
	Disk       map[string][][2]float64 `json:"disk"`
	Requests   [][2]float64            `json:"requests"`
	Errors     [][2]float64            `json:"errors"`
	P95        [][2]float64            `json:"p95"`
	Deploys    []Event                 `json:"deploys"`
	Containers struct {
		CPU    map[string][][2]float64 `json:"cpu"`
		Memory map[string][][2]float64 `json:"memory"`
	} `json:"containers"`
}

// Metrics returns a server's charts for a range: 1h, 24h, 7d or 30d.
func (c *Client) Metrics(ctx context.Context, serverID, rangeName string) (Charts, error) {
	var out Charts
	err := c.do(ctx, http.MethodGet, "/v1/servers/"+serverID+"/metrics?range="+url.QueryEscape(rangeName), nil, &out)
	return out, err
}

// TraceRow is one request in the Traces list.
type TraceRow struct {
	ID        string    `json:"id"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    *int      `json:"status"`
	StartedAt time.Time `json:"startedAt"`
	TotalMs   int       `json:"totalMs"`
	Lead      string    `json:"lead"`
	Short     string    `json:"short"`
}

// TraceStep is one step of a request, with how its time is known:
// measured, matched (by time) or worked_out.
type TraceStep struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Ms     int    `json:"ms"`
	Offset int    `json:"offset"`
	How    string `json:"how"`
}

// Trace is one request: its steps, its sentence and its log lines.
type Trace struct {
	TraceRow
	Steps []TraceStep `json:"steps"`
	Lines []struct {
		At     time.Time `json:"at"`
		Level  string    `json:"level"`
		Source string    `json:"source"`
		Where  string    `json:"where"`
		Name   string    `json:"name"`
		Text   string    `json:"text"`
	} `json:"lines"`
}

// Traces lists requests, newest first: filter is "slow" or "all"; q is a
// request ID or an address; rng is 1h, 24h or 7d.
func (c *Client) Traces(ctx context.Context, filter, q, rng string) ([]TraceRow, error) {
	v := url.Values{"filter": {filter}, "range": {rng}}
	if q != "" {
		v.Set("q", q)
	}
	var out struct {
		Traces []TraceRow `json:"traces"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/traces?"+v.Encode(), nil, &out)
	return out.Traces, err
}

// Trace is one request by its ID.
func (c *Client) Trace(ctx context.Context, id string) (Trace, error) {
	var out Trace
	err := c.do(ctx, http.MethodGet, "/v1/traces/"+url.PathEscape(id), nil, &out)
	return out, err
}

// Incident is one incident in the list, or its detail.
type Incident struct {
	ID         string     `json:"id"`
	Ref        string     `json:"ref"`
	Title      string     `json:"title"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	FixedAt    *time.Time `json:"fixedAt"`
	Limited    bool       `json:"limited"`
	SourceName *string    `json:"sourceName"`
	Certainty  *string    `json:"certainty"`
	Where      *string    `json:"where"`
	Sentence   string     `json:"sentence"`
	Evidence   []struct {
		Area    string `json:"area"`
		Text    string `json:"text"`
		Verdict string `json:"verdict"`
	} `json:"evidence"`
	Timeline []struct {
		At   time.Time `json:"at"`
		Kind string    `json:"kind"`
		Text string    `json:"text"`
	} `json:"timeline"`
	Fix *struct {
		Title    string  `json:"title"`
		Happened string  `json:"happened"`
		Why      string  `json:"why"`
		Fix      string  `json:"fix"`
		Command  *string `json:"command"`
	} `json:"fix"`
	// Explain is a plain paragraph for a client or a manager.
	Explain  *string `json:"explain"`
	TeamNote *struct {
		Ref  string  `json:"ref"`
		Note string  `json:"note"`
		By   *string `json:"by"`
	} `json:"teamNote"`
}

// IncidentList is the Incidents screen: the counts and the incidents.
type IncidentList struct {
	Counts struct {
		Open          int `json:"open"`
		FixedThisWeek int `json:"fixedThisWeek"`
		All           int `json:"all"`
	} `json:"counts"`
	Incidents []Incident `json:"incidents"`
}

// Incidents lists incidents: status is open, fixed or all.
func (c *Client) Incidents(ctx context.Context, status string) (IncidentList, error) {
	var out IncidentList
	err := c.do(ctx, http.MethodGet, "/v1/incidents?status="+url.QueryEscape(status), nil, &out)
	return out, err
}

// IncidentDetail is one incident, by its number (INC-12) or id.
func (c *Client) IncidentDetail(ctx context.Context, ref string) (Incident, error) {
	var out Incident
	err := c.do(ctx, http.MethodGet, "/v1/incidents/"+url.PathEscape(ref), nil, &out)
	return out, err
}

// AckIncident acknowledges an incident.
func (c *Client) AckIncident(ctx context.Context, ref string) error {
	return c.do(ctx, http.MethodPost, "/v1/incidents/"+url.PathEscape(ref)+"/ack", nil, nil)
}

// ResolveIncident marks an incident fixed, with what fixed it.
func (c *Client) ResolveIncident(ctx context.Context, ref, note string) error {
	return c.do(ctx, http.MethodPost, "/v1/incidents/"+url.PathEscape(ref)+"/fix", map[string]string{"note": note}, nil)
}

// Job is a timed job wrapped with kiyesi run, as the Scheduled jobs screen shows it.
type Job struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Server struct {
		Name string `json:"name"`
	} `json:"server"`
	Schedule *struct {
		Words string `json:"words"`
	} `json:"schedule"`
	LastRun *struct {
		StartedAt  time.Time `json:"startedAt"`
		ExitCode   int       `json:"exitCode"`
		DurationMs int64     `json:"durationMs"`
	} `json:"lastRun"`
	UsualMs      *int64     `json:"usualMs"`
	NextExpected *time.Time `json:"nextExpected"`
	Status       string     `json:"status"`
	Problem      *struct {
		Text string `json:"text"`
	} `json:"problem"`
	Runs []struct {
		StartedAt  time.Time `json:"startedAt"`
		ExitCode   *int      `json:"exitCode"`
		DurationMs *int64    `json:"durationMs"`
		LastLines  []string  `json:"lastLines"`
	} `json:"runs"`
}

// Jobs lists the timed jobs the person can see.
func (c *Client) Jobs(ctx context.Context) ([]Job, error) {
	var out struct {
		Jobs []Job `json:"jobs"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/jobs", nil, &out)
	return out.Jobs, err
}

// JobDetail is one job with its recent runs.
func (c *Client) JobDetail(ctx context.Context, id string) (Job, error) {
	var out Job
	err := c.do(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), nil, &out)
	return out, err
}

// DeployVerdict is a deploy with its verdict.
type DeployVerdict struct {
	ID      string    `json:"id"`
	App     string    `json:"app"`
	Version string    `json:"version"`
	By      *string   `json:"by"`
	At      time.Time `json:"at"`
	Server  *struct {
		Name string `json:"name"`
	} `json:"server"`
	Status   string  `json:"status"`
	Sentence *string `json:"sentence"`
	Rollback *string `json:"rollback"`
}

// Deploys lists deploys with their verdicts, newest first: since is 24h, 7d, 30d or 90d.
func (c *Client) Deploys(ctx context.Context, since string) ([]DeployVerdict, error) {
	var out struct {
		Deploys []DeployVerdict `json:"deploys"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/deploys?since="+url.QueryEscape(since), nil, &out)
	return out.Deploys, err
}

// Database is one watched database, as the Databases screen shows it.
type Database struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Label  string `json:"label"`
	Where  string `json:"where"`
	Server struct {
		Name string `json:"name"`
	} `json:"server"`
	SizeBytes      *int64     `json:"sizeBytes"`
	LimitBytes     *int64     `json:"limitBytes"`
	Connections    *int64     `json:"connections"`
	MaxConnections *int64     `json:"maxConnections"`
	SlowLastHour   *int64     `json:"slowLastHour"`
	NewestBackupAt *time.Time `json:"newestBackupAt"`
	FullAt         *time.Time `json:"fullAt"`
	Error          *string    `json:"error"`
	Status         string     `json:"status"`
	Problems       []struct {
		Sentence string `json:"sentence"`
	} `json:"problems"`
}

// Databases lists the databases the person can see.
func (c *Client) Databases(ctx context.Context) ([]Database, error) {
	var out struct {
		Databases []Database `json:"databases"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/databases", nil, &out)
	return out.Databases, err
}

// ServerCost is one server's cost against its use.
type ServerCost struct {
	Server struct {
		Name string `json:"name"`
	} `json:"server"`
	Size  string `json:"size"`
	Price *struct {
		Monthly  float64 `json:"monthly"`
		Currency string  `json:"currency"`
	} `json:"price"`
	CPUPeak    *float64 `json:"cpuPeak"`
	MemoryPeak *float64 `json:"memoryPeak"`
	Suggestion struct {
		Kind     string   `json:"kind"`
		Sentence string   `json:"sentence"`
		Change   *float64 `json:"change"`
	} `json:"suggestion"`
	Converted *struct {
		Monthly  float64 `json:"monthly"`
		Currency string  `json:"currency"`
	} `json:"converted"`
}

// Costs is the Costs screen: totals per currency and each server.
type Costs struct {
	Currency   *string `json:"currency"`
	InCurrency *struct {
		Currency     string   `json:"currency"`
		Monthly      float64  `json:"monthly"`
		Save         float64  `json:"save"`
		NotConverted []string `json:"notConverted"`
	} `json:"inCurrency"`
	Rate *struct {
		Day    string `json:"day"`
		Source string `json:"source"`
	} `json:"rate"`
	RateWarning *struct {
		Percent  float64 `json:"percent"`
		Since    string  `json:"since"`
		From     float64 `json:"from"`
		To       float64 `json:"to"`
		Currency string  `json:"currency"`
	} `json:"rateWarning"`
	Totals []struct {
		Currency string  `json:"currency"`
		Monthly  float64 `json:"monthly"`
		Save     float64 `json:"save"`
	} `json:"totals"`
	Servers []ServerCost `json:"servers"`
}

// CostList is each server's cost against its use; currency, when given,
// shows it in that currency for this request only.
func (c *Client) CostList(ctx context.Context, currency string) (Costs, error) {
	var out Costs
	path := "/v1/costs"
	if currency != "" {
		path += "?currency=" + url.QueryEscape(currency)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// NotFoundError is a 404, with the service's own words when it gave any,
// such as which project does not exist. errors.Is(err, ErrNotFound) holds.
type NotFoundError struct{ Message string }

func (e *NotFoundError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return ErrNotFound.Error()
}

// Is makes errors.Is(err, ErrNotFound) true.
func (e *NotFoundError) Is(target error) bool { return target == ErrNotFound }

// Finding is one problem on one server, with why it matters and its fix.
type Finding struct {
	Server struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"server"`
	Check      string    `json:"check"`
	CheckName  string    `json:"checkName"`
	Severity   string    `json:"severity"`
	Confidence *string   `json:"confidence"`
	Sentence   string    `json:"sentence"`
	Why        string    `json:"why"`
	Fix        string    `json:"fix"`
	ScannedAt  time.Time `json:"scannedAt"`
}

// Findings lists every finding on the servers the person can see, worst
// first; severity narrows it to critical, warning or info.
func (c *Client) Findings(ctx context.Context, severity string) ([]Finding, error) {
	var out struct {
		Findings []Finding `json:"findings"`
	}
	path := "/v1/findings"
	if severity != "" {
		path += "?severity=" + url.QueryEscape(severity)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Findings, err
}
