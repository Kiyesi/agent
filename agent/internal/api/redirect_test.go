package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A redirect is never followed, so a signed-in session's request never
// reaches another address.
func TestTheClientFollowsNoRedirect(t *testing.T) {
	var reached atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer elsewhere.Close()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer service.Close()
	if _, err := New(service.URL, "kss_token").Servers(context.Background()); err == nil {
		t.Error("a redirect was taken as an answer")
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the redirect was followed %d times", n)
	}
}
