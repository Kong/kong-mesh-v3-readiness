package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in              string
		maj, min, patch int
		ok              bool
	}{
		{"2.14.0", 2, 14, 0, true},
		{"2.9.0", 2, 9, 0, true},
		{"v2.14.1", 2, 14, 1, true},
		{"2.14.7-rc1", 2, 14, 7, true},
		{"2.14.0+build.5", 2, 14, 0, true},
		{"3.0.0", 3, 0, 0, true},
		{"2.14", 0, 0, 0, false},
		{"dev", 0, 0, 0, false},
		{"x.y.z", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}
	for _, c := range cases {
		maj, min, patch, ok := parseSemver(c.in)
		if ok != c.ok || (ok && (maj != c.maj || min != c.min || patch != c.patch)) {
			t.Errorf("parseSemver(%q) = (%d,%d,%d,%v), want (%d,%d,%d,%v)",
				c.in, maj, min, patch, ok, c.maj, c.min, c.patch, c.ok)
		}
	}
}

func TestBehind(t *testing.T) {
	// latest = 2.14.5
	const lMin, lPatch = 14, 5
	cases := []struct {
		maj, min, patch int
		want            bool
	}{
		{2, 14, 4, true},  // older patch
		{2, 14, 5, false}, // current
		{2, 14, 6, false}, // ahead patch
		{2, 13, 9, true},  // older minor
		{2, 11, 0, true},  // much older minor
		{2, 15, 0, false}, // newer minor
		{3, 0, 0, false},  // 3.x is beyond the 2.x upgrade source
		{1, 8, 0, true},   // 1.x must reach 2.14 first
		{0, 0, 0, true},   // pre-2.x / dev build is not a valid upgrade source
	}
	for _, c := range cases {
		if got := behind(c.maj, c.min, c.patch, lMin, lPatch); got != c.want {
			t.Errorf("behind(%d.%d.%d, latest 2.%d.%d) = %v, want %v",
				c.maj, c.min, c.patch, lMin, lPatch, got, c.want)
		}
	}
}

func TestLatestZoneVersion(t *testing.T) {
	mk := func(vs ...string) zoneOverview {
		var zo zoneOverview
		for _, v := range vs {
			var s zoneSubscription
			s.Version.KumaCp.Version = v
			zo.ZoneInsight.Subscriptions = append(zo.ZoneInsight.Subscriptions, s)
		}
		return zo
	}
	if v, ok := latestZoneVersion(mk("2.13.0", "2.14.0")); !ok || v != "2.14.0" {
		t.Errorf("got (%q,%v), want freshest 2.14.0", v, ok)
	}
	if v, ok := latestZoneVersion(mk("2.14.0", "")); !ok || v != "2.14.0" {
		t.Errorf("got (%q,%v), want earlier non-empty 2.14.0", v, ok)
	}
	if _, ok := latestZoneVersion(mk()); ok {
		t.Errorf("no subscriptions should return ok=false")
	}
	if _, ok := latestZoneVersion(mk("", "")); ok {
		t.Errorf("all-empty versions should return ok=false")
	}
}

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

		got, err := fetchLatestPatch(context.Background(), srv.Client(), 14)
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
		if _, err := fetchLatestPatch(context.Background(), srv.Client(), 14); err == nil {
			t.Errorf("want error when no 2.14.x release exists")
		}
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		t.Cleanup(srv.Close)
		githubReleasesURL = srv.URL
		if _, err := fetchLatestPatch(context.Background(), srv.Client(), 14); err == nil {
			t.Errorf("want error on non-200 response")
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
		got, err := fetchLatestPatch(context.Background(), srv.Client(), 14)
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
		// Reject a non-http scheme even if labelled rel="next".
		`<ftp://evil/x>; rel="next"`: "",
	}
	for in, want := range cases {
		if got := nextReleaseLink(in); got != want {
			t.Errorf("nextReleaseLink(%q) = %q, want %q", in, got, want)
		}
	}
}

// auditVersion audits a stub CP with the version-currency check enabled.
func auditVersion(t *testing.T, latest string, handlers map[string]http.HandlerFunc) *report {
	t.Helper()
	srv := cpServer(t, handlers)
	c, err := newClient(srv.URL, "", 10*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{checkVersionCurrency: true, latestPatch: latest})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	return rep
}

func versionFinding(r *report) (finding, bool) {
	for _, f := range r.findings {
		if f.category == cpVersionCategory {
			return f, true
		}
	}
	return finding{}, false
}

func hasExample(f finding, want string) bool {
	for _, ex := range f.examples {
		if ex == want {
			return true
		}
	}
	return false
}

func TestCheckControlPlaneVersionsConnected(t *testing.T) {
	t.Run("behind latest patch is a blocker", func(t *testing.T) {
		rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.9.0","mode":"zone"}`))
			},
		})
		f, ok := versionFinding(rep)
		if !ok {
			t.Fatalf("no %q finding; findings=%v", cpVersionCategory, rep.findings)
		}
		if f.severity != blocker {
			t.Errorf("severity = %v, want blocker", f.severity)
		}
		if !hasExample(f, "control plane (2.9.0)") {
			t.Errorf("examples = %v, want to include the connected CP", f.examples)
		}
	})

	t.Run("current patch is silent", func(t *testing.T) {
		rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0","mode":"zone"}`))
			},
		})
		if _, ok := versionFinding(rep); ok {
			t.Errorf("current CP produced a version finding")
		}
	})
}

func TestCheckControlPlaneVersionsGlobalFanout(t *testing.T) {
	zones := `{"total":2,"items":[
		{"type":"ZoneInsight","name":"zone-a","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.14.0"}}}]}},
		{"type":"ZoneInsight","name":"zone-b","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.13.5"}}}]}}
	],"next":null}`
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0","mode":"global"}`))
		},
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"mode":"global","environment":"universal"}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(zones))
		},
	})
	f, ok := versionFinding(rep)
	if !ok {
		t.Fatalf("no %q finding; findings=%v", cpVersionCategory, rep.findings)
	}
	if !hasExample(f, "zone zone-b (2.13.5)") {
		t.Errorf("examples = %v, want the behind zone-b", f.examples)
	}
	if hasExample(f, "zone zone-a (2.14.0)") {
		t.Errorf("examples = %v, must not flag the current zone-a", f.examples)
	}
	if hasExample(f, "control plane (2.14.0)") {
		t.Errorf("examples = %v, must not flag the current global CP", f.examples)
	}
}

// A global CP whose /config is unreadable (e.g. RBAC without --token) reports no
// mode (GET / carries none), yet its connected zones must still be version-checked
// — skipping them would be a fake-clean. The fan-out must run on unknown mode.
func TestGlobalVersionFanoutWhenModeUnknown(t *testing.T) {
	zones := `{"total":1,"items":[
		{"type":"ZoneInsight","name":"zone-old","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.11.2"}}}]}}
	],"next":null}`
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		// Default cpServer "/" returns version 2.14.0 with NO mode field.
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden) // mode stays unknown
			_, _ = w.Write([]byte(`{"status":403}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(zones))
		},
	})
	if rep.cp.Mode != "" {
		t.Fatalf("precondition: mode should be unknown, got %q", rep.cp.Mode)
	}
	f, ok := versionFinding(rep)
	if !ok {
		t.Fatalf("stale zone silently skipped on a mode-unknown global; findings=%v", rep.findings)
	}
	if !hasExample(f, "zone zone-old (2.11.2)") {
		t.Errorf("examples = %v, want the stale zone-old", f.examples)
	}
}

// When mode is unknown and the CP is actually a zone/standalone, /zones+insights
// returns 404 — "not a global", not a coverage gap. The fan-out is attempted (mode
// unknown) but the 404 must be skipped silently, not recorded as a version gap.
func TestZoneCPNoVersionFanoutGap(t *testing.T) {
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		// Default cpServer "/" carries no mode, so the fan-out is attempted.
		"/zones+insights": func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		},
	})
	if _, ok := gapForPath(rep, "/zones+insights (versions)"); ok {
		t.Errorf("a 404 on /zones+insights must not record a zone-version coverage gap")
	}
}

func TestLatestVersionWrongMinorIsGap(t *testing.T) {
	rep := auditVersion(t, "2.13.5", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0","mode":"zone"}`))
		},
	})
	if _, ok := gapForPath(rep, "--latest-version"); !ok {
		t.Fatalf("a non-2.14 --latest-version should record a gap; gaps=%v", rep.coverage)
	}
	if _, ok := versionFinding(rep); ok {
		t.Errorf("must not produce a contradictory finding for a wrong-minor baseline")
	}
}

func TestVersionCurrencyUnknownIsGap(t *testing.T) {
	rep := auditVersion(t, "", nil)
	if _, ok := gapForPath(rep, "github.com/kumahq/kuma/releases"); !ok {
		t.Fatalf("empty latest patch should record a coverage gap; gaps=%v", rep.coverage)
	}
	if _, ok := versionFinding(rep); ok {
		t.Errorf("unknown latest must not produce a version finding")
	}
}

func TestVersionCheckOffByDefault(t *testing.T) {
	srv := cpServer(t, nil)
	c, err := newClient(srv.URL, "", 10*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{}) // checkVersionCurrency: false
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, ok := versionFinding(rep); ok {
		t.Errorf("version check ran without being enabled")
	}
	if _, ok := gapForPath(rep, "github.com/kumahq/kuma/releases"); ok {
		t.Errorf("disabled version check recorded a gap")
	}
}

func TestFlagIfBehindUnparseableIsGap(t *testing.T) {
	a := &auditor{rep: &report{}}
	a.flagIfBehind("unknown", "control plane", 14, 0, "detail")
	if len(a.rep.findings) != 0 {
		t.Errorf("unparseable version produced a finding, want a gap only")
	}
	if _, ok := gapForPath(a.rep, "version (control plane)"); !ok {
		t.Errorf("unparseable version should record a coverage gap; gaps=%v", a.rep.coverage)
	}
}
