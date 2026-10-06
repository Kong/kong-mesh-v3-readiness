package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchLatestPatch(t *testing.T) {
	orig := githubReleasesURL
	t.Cleanup(func() { githubReleasesURL = orig })

	t.Run("picks highest 2.14.x, ignoring prerelease/draft/other lines", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `[
				{"tag_name":"3.0.0","draft":false,"prerelease":false},
				{"tag_name":"2.14.99","draft":true,"prerelease":false},
				{"tag_name":"2.14.9","draft":false,"prerelease":true},
				{"tag_name":"2.14.7","draft":false,"prerelease":false},
				{"tag_name":"2.14.3","draft":false,"prerelease":false},
				{"tag_name":"2.13.8","draft":false,"prerelease":false}
			]`)
		}))
		t.Cleanup(srv.Close)
		githubReleasesURL = srv.URL

		got, err := fetchLatestPatch(context.Background(), srv.Client())
		if err != nil {
			t.Fatalf("fetchLatestPatch: %v", err)
		}
		if got != "2.14.7" {
			t.Errorf("got %q, want 2.14.7", got)
		}
	})

	t.Run("no matching minor is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `[{"tag_name":"2.13.8","draft":false,"prerelease":false}]`)
		}))
		t.Cleanup(srv.Close)
		githubReleasesURL = srv.URL
		if _, err := fetchLatestPatch(context.Background(), srv.Client()); err == nil {
			t.Errorf("want error when no 2.14.x release exists")
		}
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		t.Cleanup(srv.Close)
		githubReleasesURL = srv.URL
		if _, err := fetchLatestPatch(context.Background(), srv.Client()); err == nil {
			t.Errorf("want error on non-200 response")
		}
	})

	t.Run("cap reached with more pages is an error, not a stale best", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Always advertise a next page → traversal never naturally ends, so the
			// page cap is hit. A 2.14.x is present, but we must not return it as
			// authoritative since unread pages might hold a higher patch.
			w.Header().Set("Link", `<`+srv.URL+`?page=next>; rel="next"`)
			_, _ = io.WriteString(w, `[{"tag_name":"2.14.1","draft":false,"prerelease":false}]`)
		}))
		t.Cleanup(srv.Close)
		githubReleasesURL = srv.URL
		if _, err := fetchLatestPatch(context.Background(), srv.Client()); err == nil {
			t.Errorf("hitting the page cap mid-traversal must be an error, not a (stale) best")
		}
	})

	t.Run("follows pagination to find a patch on a later page", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Page 1 has only an older line; the true latest 2.14.x is on page 2,
			// reached via the Link header.
			if r.URL.Query().Get("page") == "2" {
				_, _ = io.WriteString(w, `[{"tag_name":"2.14.5","draft":false,"prerelease":false}]`)
				return
			}
			w.Header().Set("Link", `<`+srv.URL+`?page=2>; rel="next"`)
			_, _ = io.WriteString(w, `[{"tag_name":"2.13.8","draft":false,"prerelease":false}]`)
		}))
		t.Cleanup(srv.Close)
		githubReleasesURL = srv.URL
		got, err := fetchLatestPatch(context.Background(), srv.Client())
		if err != nil {
			t.Fatalf("fetchLatestPatch: %v", err)
		}
		if got != "2.14.5" {
			t.Errorf("got %q, want 2.14.5 (from page 2)", got)
		}
	})
}

func TestNextReleaseLink(t *testing.T) {
	cases := map[string]string{
		`<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"`: "https://api.github.com/x?page=2",
		`<https://api.github.com/x?page=9>; rel="last"`:                                                "",
		``:        "",
		`garbage`: "",
		// Reject a non-http scheme even if labeled rel="next".
		`<ftp://evil/x>; rel="next"`: "",
	}
	for in, want := range cases {
		if got := nextReleaseLink(in); got != want {
			t.Errorf("nextReleaseLink(%q) = %q, want %q", in, got, want)
		}
	}
}
