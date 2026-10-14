package api

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// MapRow is one item on the data map.
type MapRow struct {
	ServerID   string  `json:"serverId"`
	ServerName string  `json:"serverName"`
	Kind       string  `json:"kind"`
	Name       string  `json:"name"`
	Provider   *string `json:"provider"`
	Place      *string `json:"place"`
	Country    *string `json:"country"`
	Confidence string  `json:"confidence"`
	Payment    bool    `json:"payment"`
	Managed    bool    `json:"managed"`
	Private    bool    `json:"private"`
	Result     string  `json:"result"`
}

// DataMap is where every server, database and backup sits.
type DataMap struct {
	Home *struct {
		Code   string `json:"code"`
		Name   string `json:"name"`
		Chosen bool   `json:"chosen"`
	} `json:"home"`
	Counts struct {
		Mapped   int `json:"mapped"`
		Outside  int `json:"outside"`
		Inside   int `json:"inside"`
		Review   int `json:"review"`
		MustMove int `json:"mustMove"`
	} `json:"counts"`
	Rows   []MapRow `json:"rows"`
	IPinfo bool     `json:"ipinfo"`
}

// DataMap reads the data map.
func (c *Client) DataMap(ctx context.Context) (DataMap, error) {
	var out DataMap
	err := c.do(ctx, http.MethodGet, "/v1/data-map", nil, &out)
	return out, err
}

// Tip is an improvement that is not urgent.
type Tip struct {
	ID         string `json:"id"`
	Sentence   string `json:"sentence"`
	Why        string `json:"why"`
	Fix        string `json:"fix"`
	ServerID   string `json:"serverId"`
	ServerName string `json:"serverName"`
}

// Tips lists the tips, for one server when serverID is set.
func (c *Client) Tips(ctx context.Context, serverID string) ([]Tip, error) {
	var out struct {
		Tips []Tip `json:"tips"`
	}
	path := "/v1/tips"
	if serverID != "" {
		path += "?server=" + url.QueryEscape(serverID)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Tips, err
}

// Advisory is software past its end of life, or a package with published fixes.
type Advisory struct {
	Kind        string    `json:"kind"`
	Level       string    `json:"level"`
	Sentence    string    `json:"sentence"`
	Why         string    `json:"why"`
	Fix         string    `json:"fix"`
	IDs         []string  `json:"ids"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	ServerID    string    `json:"serverId"`
	ServerName  string    `json:"serverName"`
}

// Advisories lists the advisories, for one server when serverID is set.
func (c *Client) Advisories(ctx context.Context, serverID string) ([]Advisory, *time.Time, error) {
	var out struct {
		Advisories []Advisory `json:"advisories"`
		CheckedAt  *time.Time `json:"checkedAt"`
	}
	path := "/v1/advisories"
	if serverID != "" {
		path += "?server=" + url.QueryEscape(serverID)
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Advisories, out.CheckedAt, err
}
