package api

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Preflight is the answer to "safe to deploy?" for one server.
type Preflight struct {
	Server struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Project *struct {
			Name string `json:"name"`
		} `json:"project"`
		Environment *string `json:"environment"`
	} `json:"server"`
	Answer string `json:"answer"`
	Checks []struct {
		ID       string `json:"id"`
		Label    string `json:"label"`
		Status   string `json:"status"`
		Sentence string `json:"sentence"`
	} `json:"checks"`
	DoFirst   []string   `json:"doFirst"`
	ScannedAt *time.Time `json:"scannedAt"`
}

// Preflight asks whether it is safe to deploy to a server, by name or id.
func (c *Client) Preflight(ctx context.Context, server string) (Preflight, error) {
	var out Preflight
	err := c.do(ctx, http.MethodGet, "/v1/preflight?server="+url.QueryEscape(server), nil, &out)
	return out, err
}

// Drill is a fire drill and what each step did.
type Drill struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	StartedBy string    `json:"startedBy"`
	Done      bool      `json:"done"`
	Summary   string    `json:"summary"`
	Steps     []struct {
		Step               int        `json:"step"`
		Name               string     `json:"name"`
		RealMinutes        int        `json:"realMinutes"`
		SentAt             *time.Time `json:"sentAt"`
		Via                *string    `json:"via"`
		Delivered          *bool      `json:"delivered"`
		Reason             *string    `json:"reason"`
		DeliveredInSeconds *int       `json:"deliveredInSeconds"`
		AckedInMinutes     *int       `json:"ackedInMinutes"`
	} `json:"steps"`
}

// StartDrill sends a practice incident through the team's escalation steps.
func (c *Client) StartDrill(ctx context.Context) (Drill, error) {
	var out struct {
		Drill Drill `json:"drill"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/drills", map[string]any{}, &out)
	return out.Drill, err
}

// LastDrill is the team's latest fire drill, or nil.
func (c *Client) LastDrill(ctx context.Context) (*Drill, error) {
	var out struct {
		Drill *Drill `json:"drill"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/drills/latest", nil, &out)
	return out.Drill, err
}

// Passport is a server's passport, written by Kiyesi from what it holds.
type Passport struct {
	Server string `json:"server"`
	Label  string `json:"label"`
	Note   *struct {
		Text string  `json:"text"`
		By   *string `json:"by"`
	} `json:"note"`
	Runs []struct {
		Name    string `json:"name"`
		Image   string `json:"image"`
		Restart string `json:"restart"`
	} `json:"runs"`
	Ports []struct {
		Port   string `json:"port"`
		What   string `json:"what"`
		Status string `json:"status"`
	} `json:"ports"`
	Jobs []struct {
		Name     string `json:"name"`
		Schedule string `json:"schedule"`
		Status   string `json:"status"`
	} `json:"jobs"`
	Usual []struct {
		Title   string `json:"title"`
		Command string `json:"command"`
	} `json:"usual"`
	Facts     [][2]string `json:"facts"`
	People    [][2]string `json:"people"`
	DependsOn []struct {
		Name string `json:"name"`
		What string `json:"what"`
	} `json:"dependsOn"`
	Changes []struct {
		At   time.Time `json:"at"`
		Text string    `json:"text"`
	} `json:"changes"`
}

// Passport reads a server's passport, by the server's id.
func (c *Client) Passport(ctx context.Context, serverID string) (Passport, error) {
	var out Passport
	err := c.do(ctx, http.MethodGet, "/v1/servers/"+url.PathEscape(serverID)+"/passport", nil, &out)
	return out, err
}

// PassportPDF is a server's passport as a PDF.
func (c *Client) PassportPDF(ctx context.Context, serverID string) ([]byte, error) {
	return c.send(ctx, http.MethodGet, "/v1/servers/"+url.PathEscape(serverID)+"/passport/pdf", nil)
}

// SharePassport makes a read-only link to the passport that lasts 7 days.
func (c *Client) SharePassport(ctx context.Context, serverID string) (Share, error) {
	var out Share
	err := c.do(ctx, http.MethodPost, "/v1/servers/"+url.PathEscape(serverID)+"/passport/share", map[string]any{}, &out)
	return out, err
}
