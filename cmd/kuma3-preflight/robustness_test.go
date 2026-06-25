package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cpServer starts a stub CP: GET / returns a valid Kuma index, and each path in
// handlers gets its handler; every other path answers an empty collection.
func cpServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		if r.URL.Path == "/" {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0"}`))
			return
		}
		writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func gapForPath(r *report, path string) (coverageGap, bool) {
	for _, g := range r.coverage {
		if g.path == path {
			return g, true
		}
	}
	return coverageGap{}, false
}

// TestNonKumaEndpointReportsFriendlyError: pointing --address at a 200 endpoint
// whose body is not a JSON CP index (e.g. an HTML login/ingress page, or a wrong
// subpath like /gui) must fail as "not a Kuma control plane" — never leak a raw
// JSON decode error ("invalid character '<'") that obscures the real problem.
func TestNonKumaEndpointReportsFriendlyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>login</body></html>"))
	}))
	t.Cleanup(srv.Close)
	c, err := newClient(srv.URL, "", 10*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	_, err = audit(context.Background(), c, auditOptions{})
	if err == nil {
		t.Fatal("audit of a non-Kuma HTML endpoint returned no error (would be a false green)")
	}
	if !strings.Contains(err.Error(), "does not look like a Kuma control plane") {
		t.Errorf("error = %q, want it to mention 'does not look like a Kuma control plane'", err)
	}
	if strings.Contains(err.Error(), "invalid character") || strings.Contains(err.Error(), "decoding") {
		t.Errorf("error leaked a raw JSON decode message instead of the friendly one: %q", err)
	}
}

// TestConfigForbiddenDegradesToGap: a 403 on /config (Kong Mesh RBAC) must not
// abort the audit — it becomes a coverage gap and the run is inconclusive.
func TestConfigForbiddenDegradesToGap(t *testing.T) {
	srv := cpServer(t, map[string]http.HandlerFunc{
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":403}`))
		},
	})
	c, err := newClient(srv.URL, "", 10*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit aborted on /config 403, want graceful degradation: %v", err)
	}
	g, ok := gapForPath(rep, "/config")
	if !ok {
		t.Fatalf("no /config coverage gap recorded; gaps=%v", rep.coverage)
	}
	if !strings.Contains(g.reason, "--token") {
		t.Errorf("/config gap reason should mention --token, got %q", g.reason)
	}
	if rep.status() != statusInconclusive {
		t.Errorf("status = %q, want %q", rep.status(), statusInconclusive)
	}
}

// TestGlobalZonesInsightsForbiddenDegradesToGap: on a global CP, a 403 on
// /zones+insights must not abort the fan-out — it becomes a coverage gap.
func TestGlobalZonesInsightsForbiddenDegradesToGap(t *testing.T) {
	srv := cpServer(t, map[string]http.HandlerFunc{
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			// Universal global → no global-on-k8s blocker, so the only finding is the gap.
			writeJSON(w, []byte(`{"mode":"global","environment":"universal"}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":403}`))
		},
	})
	c, err := newClient(srv.URL, "", 10*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit aborted on /zones+insights 403, want graceful degradation: %v", err)
	}
	if rep.cp.Mode != "global" {
		t.Errorf("mode = %q, want global (stamped from /config)", rep.cp.Mode)
	}
	if _, ok := gapForPath(rep, "/zones+insights"); !ok {
		t.Fatalf("no /zones+insights coverage gap recorded; gaps=%v", rep.coverage)
	}
	if rep.status() != statusInconclusive {
		t.Errorf("status = %q, want %q", rep.status(), statusInconclusive)
	}
}
