package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDataplaneVersionIncompatibleReported checks that a proxy the CP reports as
// version-incompatible (kumaCpCompatible=false) surfaces as a warning, while a
// compatible one does not.
func TestDataplaneVersionIncompatibleReported(t *testing.T) {
	insights := `{"total":2,"items":[
		{"type":"DataplaneOverview","mesh":"default","name":"old-dp",
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.5.0","kumaCpCompatible":false}}}]}},
		{"type":"DataplaneOverview","mesh":"default","name":"new-dp",
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.9.0","kumaCpCompatible":true}}}]}}
	],"next":null}`
	m := auditResponses(t, map[string]string{"/dataplanes+insights": insights})
	f, ok := findFinding(m, "warning", "Dataplane version", "Dataplane is version-incompatible with the control plane")
	if !ok {
		t.Fatalf("expected a version-incompatibility warning, got %+v", m.Findings)
	}
	if f.Count != 1 {
		t.Errorf("count = %d, want 1 (only the incompatible proxy)", f.Count)
	}
	if len(f.Examples) == 0 || !strings.Contains(f.Examples[0], "old-dp") {
		t.Errorf("example should name old-dp, got %+v", f.Examples)
	}
}

// TestDataplaneMetricsOverrideReported checks that a per-proxy metrics backend on
// a Dataplane surfaces as a warning (deprecated → MeshMetric).
func TestDataplaneMetricsOverrideReported(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"networking": map[string]any{"inbound": []any{map[string]any{"port": 8080}}},
		"metrics":    map[string]any{"type": "prometheus", "conf": map[string]any{"port": 5670}},
	})
	if _, ok := findFinding(m, "warning", "Dataplane metrics", "Dataplane has a per-proxy metrics override"); !ok {
		t.Errorf("expected a per-proxy metrics warning, got %+v", m.Findings)
	}
}

// TestInspectDataplanesDetectsEnvoyDNSFilter exercises the opt-in deep check:
// with --inspect-dataplanes the audit fetches each proxy's config dump and flags
// the legacy Envoy DNS filter, and skips entirely when the flag is 0.
func TestInspectDataplanesDetectsEnvoyDNSFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.9.0","mode":"zone"}`)
		case r.URL.Path == "/meshes":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"Mesh","name":"default"}],"next":null}`)
		case r.URL.Path == "/dataplanes":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"Dataplane","mesh":"default","name":"dp-1"}],"next":null}`)
		case strings.HasSuffix(r.URL.Path, "/dataplanes/dp-1/xds"):
			_, _ = io.WriteString(w, `{"configs":[{"dynamic_listeners":[{"name":"kuma:dns","filter_chains":[{"filters":[{"name":"envoy.filters.udp.dns_filter"}]}]}]}]}`)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := newClient(srv.URL, "", 30*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	// Flag off: no inspection, no DNS finding.
	off, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit (off): %v", err)
	}
	if _, ok := findFinding(off.toModel(""), "warning", "Dataplane DNS", "Dataplane uses the legacy Envoy DNS filter"); ok {
		t.Error("DNS filter must not be inspected when --inspect-dataplanes is 0")
	}

	// Flag on: the config dump is fetched and the DNS filter detected.
	on, err := audit(context.Background(), c, auditOptions{inspectDataplanes: 5})
	if err != nil {
		t.Fatalf("audit (on): %v", err)
	}
	if _, ok := findFinding(on.toModel(""), "warning", "Dataplane DNS", "Dataplane uses the legacy Envoy DNS filter"); !ok {
		t.Errorf("expected an Envoy DNS filter warning, got %+v", on.toModel("").Findings)
	}
}
