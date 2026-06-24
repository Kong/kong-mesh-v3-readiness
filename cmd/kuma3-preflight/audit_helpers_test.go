package main

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
  "runtime": {"kubernetes": {
    "injector": {
      "unifiedResourceNamingEnabled": true,
      "ebpf": {"enabled": false}
    },
    "workloadLabels": ["app.kubernetes.io/name"]
  }}
}`

// auditResponses audits a mock control plane that serves the given path->JSON
// body map. GET / returns a Kuma index, GET /config returns a 3.0-ready config,
// and any unlisted collection returns an empty list, so a test declares only the
// endpoints it cares about. The report is rendered to JSON and parsed back, so
// assertions run against the actual serialized JSON contract rather than the
// in-memory report.
func auditResponses(t *testing.T, responses map[string]string) reportModel {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if body, ok := responses[r.URL.Path]; ok {
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

	c, err := newClient(srv.URL, "", 30*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	out, err := renderJSON(rep.toModel(""))
	if err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	var m reportModel
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("unmarshal rendered JSON: %v", err)
	}
	return m
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

func findFinding(m reportModel, severity, category, title string) (findingModel, bool) {
	for _, f := range m.Findings {
		if f.Severity == severity && f.Category == category && f.Title == title {
			return f, true
		}
	}
	return findingModel{}, false
}
