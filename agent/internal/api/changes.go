package api

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// ProjectUse is something still in a project, which stops it being deleted.
type ProjectUse struct {
	One   string `json:"one"`
	Many  string `json:"many"`
	Count int    `json:"count"`
}

// RenameProject gives a project a new name.
func (c *Client) RenameProject(ctx context.Context, id, name string) error {
	return c.do(ctx, http.MethodPatch, "/v1/projects/"+url.PathEscape(id), map[string]string{"name": name}, nil)
}

// ProjectUses says what is still in a project.
func (c *Client) ProjectUses(ctx context.Context, id string) ([]ProjectUse, error) {
	var out struct {
		Uses []ProjectUse `json:"uses"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/projects/"+url.PathEscape(id)+"/uses", nil, &out)
	return out.Uses, err
}

// DeleteProject deletes an empty project.
func (c *Client) DeleteProject(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/projects/"+url.PathEscape(id), nil, nil)
}

// EditUptime changes a check's name, address or project; only what is set changes.
func (c *Client) EditUptime(ctx context.Context, id string, change map[string]any) error {
	return c.do(ctx, http.MethodPatch, "/v1/uptime/"+url.PathEscape(id), change, nil)
}

// RenameServer gives a server a new name; its agent and token are unchanged.
func (c *Client) RenameServer(ctx context.Context, id, name string) error {
	return c.do(ctx, http.MethodPatch, "/v1/servers/"+url.PathEscape(id), map[string]string{"name": name}, nil)
}

// RemoveDeploy removes a deploy marked by mistake.
func (c *Client) RemoveDeploy(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/deploys/"+url.PathEscape(id), nil, nil)
}

// LeaveTeam leaves the team these commands are for.
func (c *Client) LeaveTeam(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/team/leave", nil, nil)
}

// Session is one place you are signed in: a browser or a kiyesi command.
type Session struct {
	ID         string    `json:"id"`
	Device     string    `json:"device"`
	Address    *string   `json:"address"`
	SignedInAt time.Time `json:"signedInAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	Current    bool      `json:"current"`
}

// Sessions lists where you are signed in, newest use first.
func (c *Client) Sessions(ctx context.Context) ([]Session, error) {
	var out struct {
		Sessions []Session `json:"sessions"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/me/sessions", nil, &out)
	return out.Sessions, err
}

// EndSession signs one of your sessions out.
func (c *Client) EndSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/me/sessions/"+url.PathEscape(id), nil, nil)
}

// EndOtherSessions signs out everywhere but here; it says how many ended.
func (c *Client) EndOtherSessions(ctx context.Context) (int, error) {
	var out struct {
		Ended int `json:"ended"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/me/sessions/end-others", nil, &out)
	return out.Ended, err
}

// Credit is a team's prepaid credit: one credit is one server-day.
type Credit struct {
	Live         bool       `json:"live"`
	Balance      int        `json:"balance"`
	DaysLeft     *int       `json:"daysLeft"`
	UsedLastWeek int        `json:"usedLastWeek"`
	RunsOutOn    *time.Time `json:"runsOutOn"`
	State        struct {
		Storing  bool       `json:"storing"`
		ReadOnly bool       `json:"readOnly"`
		EraseOn  *time.Time `json:"eraseOn"`
	} `json:"state"`
	Bundles []struct {
		Credits        int     `json:"credits"`
		USD            float64 `json:"usd"`
		PerServerMonth float64 `json:"perServerMonth"`
	} `json:"bundles"`
	Lines []struct {
		At     time.Time `json:"at"`
		Amount int       `json:"amount"`
		Reason string    `json:"reason"`
	} `json:"lines"`
}

// Credit reads the team's credit.
func (c *Client) Credit(ctx context.Context) (Credit, error) {
	var out Credit
	err := c.do(ctx, http.MethodGet, "/v1/credit", nil, &out)
	return out, err
}
