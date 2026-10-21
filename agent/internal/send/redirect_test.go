package send

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A redirect from the service, or from whoever stands in for it, is never
// followed: the request and what it carries go to one address only.
func TestTheClientFollowsNoRedirect(t *testing.T) {
	var reached atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer elsewhere.Close()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer service.Close()
	c := NewClient(service.URL, "ksv_token")
	if _, err := c.Connect(context.Background(), "web-1", "Ubuntu 24.04"); err == nil {
		t.Error("a redirect was taken as an answer")
	}
	if err := c.deliver(context.Background(), []byte(`{"scan":{}}`)); err == nil {
		t.Error("a redirect was taken as delivered")
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the redirect was followed %d times", n)
	}
}
