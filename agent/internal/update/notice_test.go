package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signedRelease serves a signed list, with "security yes" when asked, and
// counts how often it is asked.
func signedRelease(t *testing.T, s signer, version string, security bool, asked *int) *httptest.Server {
	sums := newSums(version, []byte("bin"))
	if security {
		sums = append(sums, []byte("security yes\n")...)
	}
	sig := s.sign(t, sums)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			*asked++
			w.Write(sums)
		case "/SHA256SUMS.sig":
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTheUpdateLineAtMostOnceADayAndTheCheckToo(t *testing.T) {
	s := newSigner(t)
	asked := 0
	srv := signedRelease(t, s, "0.44.0", false, &asked)
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), Running: "0.43.0"}
	path := filepath.Join(t.TempDir(), "update-check.json")
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	if got := Notice(context.Background(), src, path, now); got != "kiyesi 0.44.0 is out: run sudo kiyesi update" {
		t.Fatalf("first: %q", got)
	}
	if got := Notice(context.Background(), src, path, now.Add(time.Hour)); got != "" {
		t.Fatalf("the same day again: %q", got)
	}
	if asked != 1 {
		t.Fatalf("asked get.kiyesi.dev %d times in a day", asked)
	}
	if got := Notice(context.Background(), src, path, now.Add(25*time.Hour)); !strings.Contains(got, "0.44.0") {
		t.Fatalf("the next day: %q", got)
	}
	// Up to date: nothing.
	src.Running = "0.44.0"
	if got := Notice(context.Background(), src, path, now.Add(50*time.Hour)); got != "" {
		t.Fatalf("up to date: %q", got)
	}
}

func TestASecurityReleaseSaysSo(t *testing.T) {
	s := newSigner(t)
	asked := 0
	srv := signedRelease(t, s, "0.43.1", true, &asked)
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), Running: "0.43.0"}
	got := Notice(context.Background(), src, filepath.Join(t.TempDir(), "c.json"), time.Now())
	if got != "kiyesi 0.43.1 is out and fixes a security problem: run sudo kiyesi update" {
		t.Fatal(got)
	}
	if v, sec := ParseRelease(append(newSums("0.43.1", nil), "security yes\n"...)); v != "0.43.1" || !sec {
		t.Fatal(v, sec)
	}
}

func TestOnlyTheSignedListIsBelieved(t *testing.T) {
	s, other := newSigner(t), newSigner(t)
	asked := 0
	srv := signedRelease(t, other, "9.0.0", true, &asked)
	src := Source{Base: srv.URL, Key: s.pub, HTTP: srv.Client(), Running: "0.43.0"}
	if got := Notice(context.Background(), src, filepath.Join(t.TempDir(), "c.json"), time.Now()); got != "" {
		t.Fatalf("believed a list signed by another key: %q", got)
	}
}

func TestNoNetworkIsSilentAndNotAskedAgainThatDay(t *testing.T) {
	src := Source{Base: "https://127.0.0.1:1", Key: newSigner(t).pub, HTTP: &http.Client{Timeout: time.Second}, Running: "0.43.0"}
	path := filepath.Join(t.TempDir(), "c.json")
	start := time.Now()
	if got := Notice(context.Background(), src, path, start); got != "" {
		t.Fatal(got)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("waited %s", time.Since(start))
	}
	again := time.Now()
	Notice(context.Background(), src, path, start.Add(time.Hour))
	if time.Since(again) > 100*time.Millisecond {
		t.Fatal("asked again the same day")
	}
}
