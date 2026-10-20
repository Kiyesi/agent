package api

import (
	"context"
	"net/http"
)

// FreePlan says whether the team is on the free plan, where new metrics,
// logs and traces are not kept. Any signed-in member may ask.
func (c *Client) FreePlan(ctx context.Context) (bool, error) {
	var out struct {
		Free bool `json:"free"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/credit/banner", nil, &out)
	return out.Free, err
}
