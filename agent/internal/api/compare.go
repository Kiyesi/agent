package api

import (
	"context"
	"net/http"
	"net/url"
)

// Comparison is two servers side by side, as the service sets them.
type Comparison struct {
	A           CompareSide      `json:"a"`
	B           CompareSide      `json:"b"`
	Differences int              `json:"differences"`
	Sections    []CompareSection `json:"sections"`
}

// CompareSide is one of the two servers.
type CompareSide struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Read    bool   `json:"read"`
	Covered bool   `json:"covered"`
}

// CompareSection is one part, such as packages: what differs, and how many are the same.
type CompareSection struct {
	Key  string       `json:"key"`
	Rows []CompareRow `json:"rows"`
	Same int          `json:"same"`
	// More counts the differing rows left out, past the most the service lists.
	More int `json:"more"`
}

// CompareRow is one thing and its value on each server; nil where absent.
type CompareRow struct {
	Name string  `json:"name"`
	A    *string `json:"a"`
	B    *string `json:"b"`
}

// Compare sets two servers side by side.
func (c *Client) Compare(ctx context.Context, a, b string) (Comparison, error) {
	var out Comparison
	err := c.do(ctx, http.MethodGet, "/v1/servers/compare?a="+url.QueryEscape(a)+"&b="+url.QueryEscape(b), nil, &out)
	return out, err
}
