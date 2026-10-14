package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// MetadataHost is the address every major cloud serves instance details on.
// It is on the provider's own network, link-local, and never on the internet.
const MetadataHost = "169.254.169.254"

// Metadata reads one value from the provider's metadata address. Requests to
// any other host are refused.
type Metadata interface {
	Get(ctx context.Context, method, path string, headers map[string]string) (string, error)
}

// HTTPMetadata is the real client. It never uses a proxy, and gives up
// after one second, so a scan on a machine with no metadata address is not
// slowed down.
type HTTPMetadata struct{ client *http.Client }

// NewMetadata returns the client.
func NewMetadata() *HTTPMetadata {
	return &HTTPMetadata{client: &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Get reads path from the metadata address.
func (m *HTTPMetadata) Get(ctx context.Context, method, path string, headers map[string]string) (string, error) {
	if method != http.MethodGet && method != http.MethodPut {
		return "", errors.New("only GET, and PUT for an AWS session token, are allowed")
	}
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("the path must start with /")
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+MetadataHost+path, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return strings.TrimSpace(string(body)), err
}
