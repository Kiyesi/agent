package api

import (
	"context"
	"net/http"
	"time"
)

// StatusPage is a team's public status page.
type StatusPage struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	On          bool   `json:"on"`
	Subscribers int    `json:"subscribers"`
	Views       int    `json:"viewsThisWeek"`
	Components  []struct {
		Name   string  `json:"name"`
		Status *string `json:"status"`
	} `json:"components"`
}

// StatusPost is a problem posted on a status page, with its updates.
type StatusPost struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	ResolvedAt *time.Time `json:"resolvedAt"`
	Entries    []struct {
		At    time.Time `json:"at"`
		State string    `json:"state"`
		Text  string    `json:"text"`
	} `json:"entries"`
}

// StatusPages lists the status pages you can see.
func (c *Client) StatusPages(ctx context.Context) ([]StatusPage, error) {
	var out struct {
		Pages []StatusPage `json:"pages"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/status-pages", nil, &out)
	return out.Pages, err
}

// StatusPosts lists a page's posts of the last 60 days, newest first.
func (c *Client) StatusPosts(ctx context.Context, pageID string) ([]StatusPost, error) {
	var out struct {
		Posts []StatusPost `json:"posts"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/status-pages/"+pageID+"/posts", nil, &out)
	return out.Posts, err
}

// PostStatus publishes an update: the next step of postID, or a new problem with title.
func (c *Client) PostStatus(ctx context.Context, pageID string, body map[string]string) error {
	return c.do(ctx, http.MethodPost, "/v1/status-pages/"+pageID+"/updates", body, nil)
}
