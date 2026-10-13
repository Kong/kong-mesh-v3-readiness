package preflight

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// requestCounter counts requests per path so a test can prove a read the audit
// claims to skip was never attempted.
type requestCounter struct {
	mu    sync.Mutex
	paths map[string]int
}

func newRequestCounter() *requestCounter {
	return &requestCounter{paths: map[string]int{}}
}

func (c *requestCounter) hit(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths[path]++
}

func (c *requestCounter) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paths[path]
}

// zoneConfigJSON is one zone's reported config with a single environment-agnostic
// blocker (Delta xDS off), so a test can prove the per-zone fan-out still ran.
const zoneConfigJSON = `{"mode":"zone","environment":"kubernetes","experimental":{"deltaXds":false,"sidecarContainers":false,"inboundTagsDisabled":false,"kdsEventBasedWatchdog":{"enabled":false}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":false,"ebpf":{"enabled":false}}}}}`

func zoneInsightsBody(t *testing.T, zone, cfg string) string {
	t.Helper()
	return listBody(t, map[string]any{
		"type": "ZoneOverview", "name": zone,
		"zoneInsight": map[string]any{
			"subscriptions": []any{map[string]any{"config": cfg}},
		},
	})
}

// auditWithOptionsAndCounter audits a mock control plane with explicit
// auditOptions and a per-path request counter. GET / reports a global, an
// unlisted /config serves the 3.0-ready config, and unlisted collections are
// empty, so a test declares only what it asserts on.
func auditWithOptionsAndCounter(
	t *testing.T,
	opts auditOptions,
	counter *requestCounter,
	responses map[string]string,
) Report {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.hit(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if body, ok := responses[r.URL.Path]; ok {
			_, _ = io.WriteString(w, body)
			return
		}
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.9.0","mode":"global"}`)
			return
		}
		if r.URL.Path == "/config" {
			_, _ = io.WriteString(w, readyConfigJSON)
			return
		}
		_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
	}))
	t.Cleanup(srv.Close)

	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 30 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	out, err := rep.toModel("").RenderJSON()
	if err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	var m Report
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("unmarshal rendered JSON: %v", err)
	}
	return m
}

func TestKnownGlobalSkipAuditedConfigReadsNoConfig(t *testing.T) {
	counter := newRequestCounter()
	opts := auditOptions{knownGlobal: true, skipAuditedConfig: true}
	m := auditWithOptionsAndCounter(t, opts, counter, map[string]string{
		"/zones+insights": zoneInsightsBody(t, "east", zoneConfigJSON),
	})

	if got := counter.count("/config"); got != 0 {
		t.Errorf("GET /config requests = %d, want 0", got)
	}
	if len(m.Coverage) != 0 {
		t.Errorf("coverage gaps = %+v, want none: a caller-chosen skip is not a gap", m.Coverage)
	}
	if got := m.ControlPlane.Mode; got != "global" {
		t.Errorf("mode = %q, want %q", got, "global")
	}
	if _, ok := findFinding(m, "info", cpConfigCategory, "Audited control plane settings not audited"); !ok {
		t.Errorf("missing the info finding naming the skipped scope; findings: %+v", m.Findings)
	}
	if _, ok := findFinding(m, "blocker", cpConfigCategory, "Unified resource naming not enabled"); !ok {
		t.Errorf("per-zone config was not audited; findings: %+v", m.Findings)
	}
}

func TestKnownGlobalSkipAuditedConfigDoesNotAuditGlobalOwnConfig(t *testing.T) {
	counter := newRequestCounter()
	opts := auditOptions{knownGlobal: true, skipAuditedConfig: true}
	m := auditWithOptionsAndCounter(t, opts, counter, map[string]string{
		"/config": `{"mode":"global","environment":"kubernetes","apiServer":{"authn":{"type":"adminClientCerts"}},"store":{"cache":{"enabled":false}}}`,
	})

	if _, ok := findFinding(m, "blocker", cpConfigCategory, "Global control plane on Kubernetes"); ok {
		t.Errorf("the global's own Kubernetes blocker must not be reported when the audit skips its own config")
	}
	if _, ok := findFinding(m, "blocker", cpConfigCategory, "API server adminClientCerts authn removed"); ok {
		t.Errorf("the global's own API server blocker must not be reported when the audit skips its own config")
	}
}

func TestKnownGlobalWithoutSkipStillReadsConfig(t *testing.T) {
	counter := newRequestCounter()
	opts := auditOptions{knownGlobal: true}
	m := auditWithOptionsAndCounter(t, opts, counter, nil)

	if got := counter.count("/config"); got != 1 {
		t.Errorf("GET /config requests = %d, want 1", got)
	}
	if got := m.ControlPlane.Mode; got != "global" {
		t.Errorf("mode = %q, want the asserted %q", got, "global")
	}
	if _, ok := findFinding(m, "info", cpConfigCategory, "Control plane mode differs from the caller's assertion"); !ok {
		t.Errorf("a /config mode that disagrees with the assertion must be reported; findings: %+v", m.Findings)
	}
}

func TestKnownGlobalConfigReadFailureStillAuditsZones(t *testing.T) {
	counter := newRequestCounter()
	opts := auditOptions{knownGlobal: true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.hit(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.9.0","mode":"global"}`)
		case "/config":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "/zones+insights":
			_, _ = io.WriteString(w, zoneInsightsBody(t, "east", zoneConfigJSON))
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 30 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	m := rep.toModel("")

	if _, ok := findFinding(m, "blocker", cpConfigCategory, "Unified resource naming not enabled"); !ok {
		t.Errorf("an unreadable /config must not stop the per-zone config audit; findings: %+v", m.Findings)
	}
	var gap bool
	for _, g := range m.Coverage {
		if g.Path == "/config" {
			gap = true
		}
	}
	if !gap {
		t.Errorf("an unreadable /config must stay a coverage gap; coverage: %+v", m.Coverage)
	}
}

func TestKnownGlobalAssertionSkipsModeDetectionRead(t *testing.T) {
	counter := newRequestCounter()
	opts := auditOptions{knownGlobal: true, skipAuditedConfig: true}
	m := auditWithOptionsAndCounter(t, opts, counter, nil)

	if got := counter.count("/config"); got != 0 {
		t.Errorf("GET /config requests = %d, want 0", got)
	}
	if got := m.ControlPlane.Mode; got != "global" {
		t.Errorf("mode = %q, want %q", got, "global")
	}
}

func TestKnownGlobalReportsModeWhenConfigIsUnreadable(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/":
					_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.9.0","mode":"global"}`)
				case "/config":
					http.Error(w, "unreadable", status)
				default:
					_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
				}
			}))
			t.Cleanup(srv.Close)

			c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 30 * time.Second}, nil)
			if err != nil {
				t.Fatalf("newClient: %v", err)
			}
			rep, err := audit(context.Background(), c, auditOptions{knownGlobal: true})
			if err != nil {
				t.Fatalf("audit: %v", err)
			}
			if got := rep.toModel("").ControlPlane.Mode; got != "global" {
				t.Errorf("mode = %q, want %q even when /config cannot be read", got, "global")
			}
		})
	}
}
