package api

import (
	"context"
	"net/http"
	"net/url"
)

// Badge is a server's grade badge: its image address and the README line.
type Badge struct {
	URL      string `json:"url"`
	Markdown string `json:"markdown"`
}

// BadgeOn turns a server's grade badge on, or returns it if it is on.
func (c *Client) BadgeOn(ctx context.Context, serverID string) (Badge, error) {
	var out struct {
		Badge Badge `json:"badge"`
	}
	err := c.do(ctx, http.MethodPut, "/v1/servers/"+url.PathEscape(serverID)+"/badge", map[string]any{}, &out)
	return out.Badge, err
}

// BadgeOff turns a server's grade badge off: its address stops at once.
func (c *Client) BadgeOff(ctx context.Context, serverID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/servers/"+url.PathEscape(serverID)+"/badge", nil, nil)
}
