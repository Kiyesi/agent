package api

import (
	"context"
	"net/http"
	"time"
)

// PlatformLink is one platform linked in Settings, Managed services: each
// service it names reports as its own managed server.
type PlatformLink struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Platform    string     `json:"platform"`
	Project     Project    `json:"project"`
	Environment string     `json:"environment"`
	LastSeenAt  *time.Time `json:"lastSeenAt"`
	AutoAdd     bool       `json:"autoAdd"`
	Waiting     []string   `json:"waiting"`
	Ignored     []string   `json:"ignored"`
	Services    []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"services"`
}

// PlatformLinks lists the platform links you can see.
func (c *Client) PlatformLinks(ctx context.Context) ([]PlatformLink, error) {
	var out struct {
		Links []PlatformLink `json:"links"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/platform-links", nil, &out)
	return out.Links, err
}
