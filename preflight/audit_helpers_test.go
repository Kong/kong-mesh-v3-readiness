package preflight

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// readyConfigJSON is a GET /config payload with every setting already in its
// 3.0-ready state, so checkControlPlaneConfig produces no findings. It is the
// default /config served by auditResponses; a test exercising config findings
// overrides "/config" in its responses map.
const readyConfigJSON = `{
  "mode": "zone",
  "environment": "kubernetes",
  "experimental": {
    "autoReachableServices": false,
    "deltaXds": true,
    "sidecarContainers": true,
    "inboundTagsDisabled": true,
    "kdsEventBasedWatchdog": {"enabled": true}
  },
  "defaults": {"allowAllOutbound": false},
  "runtime": {"kubernetes": {
    "injector": {
      "unifiedResourceNamingEnabled": true,
      "ebpf": {"enabled": false}
    }
  }}
}`

// auditResponses audits a mock control plane that serves the given path->JSON
// body map. GET / returns a Kuma index, GET /config returns a 3.0-ready config,
// and any unlisted collection returns an empty list, so a test declares only the
// endpoints it cares about. The report is rendered to JSON and parsed back, so
// assertions run against the actual serialized JSON contract rather than the
// in-memory report.
func auditResponses(t *testing.T, responses map[string]string) Report {
	t.Helper()
	return auditResponsesFunc(t, func(path string) (string, int, bool) {
		body, ok := responses[path]
		return body, http.StatusOK, ok
	})
}

// auditResponsesFunc is the general form of auditResponses: serve resolves a
// request path to (body, status, handled); an unhandled path falls back to the
// Kuma index, the 3.0-ready config, or an empty collection.
func auditResponsesFunc(t *testing.T, serve func(path string) (string, int, bool)) Report {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if body, status, ok := serve(r.URL.Path); ok {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
			return
		}
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.9.0","mode":"zone"}`)
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
	rep, err := audit(context.Background(), c, auditOptions{})
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

// auditWithNotFound audits a mock control plane like auditResponses, except the
// given paths answer 404 — for the collections whose "not served by this CP"
// handling a test needs to exercise.
func auditWithNotFound(t *testing.T, responses map[string]string, notFound ...string) Report {
	t.Helper()
	missing := map[string]bool{}
	for _, p := range notFound {
		missing[p] = true
	}
	return auditResponsesFunc(t, func(path string) (string, int, bool) {
		if missing[path] {
			return "", http.StatusNotFound, true
		}
		body, ok := responses[path]
		return body, http.StatusOK, ok
	})
}

// listBody marshals items into a single-page resource-list response body.
func listBody(t *testing.T, items ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"total": len(items), "items": items, "next": nil})
	if err != nil {
		t.Fatalf("marshal list: %v", err)
	}
	return string(b)
}

func findFinding(m Report, severity, category, title string) (Finding, bool) {
	for _, f := range m.Findings {
		if f.Severity == severity && f.Category == category && f.Title == title {
			return f, true
		}
	}
	return Finding{}, false
}
