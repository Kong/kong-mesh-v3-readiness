package preflight

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
// version-incompatible (kumaCpCompatible=false) surfaces as a blocker, while a
// compatible one does not.
func TestDataplaneVersionIncompatibleReported(t *testing.T) {
	insights := `{"total":2,"items":[
		{"type":"DataplaneOverview","mesh":"default","name":"old-dp",
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.5.0","kumaCpCompatible":false}}}]}},
		{"type":"DataplaneOverview","mesh":"default","name":"new-dp",
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.9.0","kumaCpCompatible":true}}}]}}
	],"next":null}`
	m := auditResponses(t, map[string]string{"/dataplanes+insights": insights})
	f, ok := findFinding(m, "blocker", "Dataplane version", "Dataplane is version-incompatible with the control plane")
	if !ok {
		t.Fatalf("expected a version-incompatibility blocker, got %+v", m.Findings)
	}
	if f.Count != 1 {
		t.Errorf("count = %d, want 1 (only the incompatible proxy)", f.Count)
	}
	if len(f.Examples) == 0 || !strings.Contains(f.Examples[0], "old-dp") {
		t.Errorf("example should name old-dp, got %+v", f.Examples)
	}
}

// TestDataplaneCoreDNSDependencyReported checks that a proxy whose insight reports
// a bundled `coredns` dependency surfaces as a blocker (legacy embedded-DNS path),
// while a proxy without it does not — no --inspect-dataplanes required.
func TestDataplaneCoreDNSDependencyReported(t *testing.T) {
	insights := `{"total":2,"items":[
		{"type":"DataplaneOverview","mesh":"default","name":"dns-dp",
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.9.0","kumaCpCompatible":true},"dependencies":{"coredns":"1.11.1"}}}]}},
		{"type":"DataplaneOverview","mesh":"default","name":"plain-dp",
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.9.0","kumaCpCompatible":true}}}]}}
	],"next":null}`
	m := auditResponses(t, map[string]string{"/dataplanes+insights": insights})
	f, ok := findFinding(m, "blocker", "Dataplane DNS", "Dataplane uses the legacy embedded CoreDNS")
	if !ok {
		t.Fatalf("expected a legacy-CoreDNS blocker, got %+v", m.Findings)
	}
	if f.Count != 1 {
		t.Errorf("count = %d, want 1 (only the proxy reporting coredns)", f.Count)
	}
	if len(f.Examples) == 0 || !strings.Contains(f.Examples[0], "dns-dp") {
		t.Errorf("example should name dns-dp, got %+v", f.Examples)
	}
}

// TestDataplaneEmbeddedDNSFeatureMissingReported checks the feature-based
// legacy-CoreDNS signal (2.14 never reports the `coredns` dependency): only a
// transparent proxy with a non-empty feature list lacking `feature-embedded-dns`
// is flagged, and a proxy matching both signals yields a single example.
func TestDataplaneEmbeddedDNSFeatureMissingReported(t *testing.T) {
	tp := `"dataplane":{"networking":{"transparentProxying":{"redirectPortInbound":15006}}},`
	sub := `"subscriptions":[{"version":{"kumaDp":{"version":"2.14.5","kumaCpCompatible":true}}}]`
	insights := `{"total":5,"items":[
		{"type":"DataplaneOverview","mesh":"default","name":"coredns-dp",` + tp + `
		 "dataplaneInsight":{` + sub + `,"metadata":{"features":["feature-unified-resource-naming"]}}},
		{"type":"DataplaneOverview","mesh":"default","name":"both-dp",` + tp + `
		 "dataplaneInsight":{"subscriptions":[{"version":{"kumaDp":{"version":"2.9.0","kumaCpCompatible":true},"dependencies":{"coredns":"1.11.1"}}}],"metadata":{"features":["feature-unified-resource-naming"]}}},
		{"type":"DataplaneOverview","mesh":"default","name":"embedded-dp",` + tp + `
		 "dataplaneInsight":{` + sub + `,"metadata":{"features":["feature-embedded-dns","feature-unified-resource-naming"]}}},
		{"type":"DataplaneOverview","mesh":"default","name":"no-metadata-dp",` + tp + `
		 "dataplaneInsight":{` + sub + `}},
		{"type":"DataplaneOverview","mesh":"default","name":"no-tp-dp",
		 "dataplane":{"networking":{"inbound":[{"port":8080}]}},
		 "dataplaneInsight":{` + sub + `,"metadata":{"features":["feature-unified-resource-naming"]}}}
	],"next":null}`
	m := auditResponses(t, map[string]string{"/dataplanes+insights": insights})
	f, ok := findFinding(m, "blocker", "Dataplane DNS", "Dataplane uses the legacy embedded CoreDNS")
	if !ok {
		t.Fatalf("expected a legacy-CoreDNS blocker, got %+v", m.Findings)
	}
	if f.Count != 2 {
		t.Errorf("count = %d, want 2 (coredns-dp and both-dp, once each), examples %+v", f.Count, f.Examples)
	}
	joined := strings.Join(f.Examples, "\n")
	for _, want := range []string{"coredns-dp", "both-dp", "(coredns 1.11.1)"} {
		if !strings.Contains(joined, want) {
			t.Errorf("examples should contain %q, got %+v", want, f.Examples)
		}
	}
	for _, unwanted := range []string{"embedded-dp", "no-metadata-dp", "no-tp-dp"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("examples should not contain %q, got %+v", unwanted, f.Examples)
		}
	}
	if !strings.Contains(f.Detail, "KUMA_DNS_PROXY_PORT=15053") {
		t.Errorf("detail should carry the pre-upgrade remediation, got %q", f.Detail)
	}
}

// TestDataplaneMetricsOverrideReported checks that a per-proxy metrics backend on
// a Dataplane surfaces as a blocker (deprecated → MeshMetric).
func TestDataplaneMetricsOverrideReported(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"networking": map[string]any{"inbound": []any{map[string]any{"port": 8080}}},
		"metrics":    map[string]any{"type": "prometheus", "conf": map[string]any{"port": 5670}},
	})
	if _, ok := findFinding(m, "blocker", "Dataplane metrics", "Dataplane has a per-proxy metrics override"); !ok {
		t.Errorf("expected a per-proxy metrics blocker, got %+v", m.Findings)
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
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 30 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	// Flag off: no inspection, no DNS finding.
	off, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit (off): %v", err)
	}
	if _, ok := findFinding(off.toModel(""), "blocker", "Dataplane DNS", "Dataplane uses the legacy Envoy DNS filter"); ok {
		t.Error("DNS filter must not be inspected when --inspect-dataplanes is 0")
	}

	// Flag on: the config dump is fetched and the DNS filter detected.
	on, err := audit(context.Background(), c, auditOptions{inspectDataplanes: 5})
	if err != nil {
		t.Fatalf("audit (on): %v", err)
	}
	if _, ok := findFinding(on.toModel(""), "blocker", "Dataplane DNS", "Dataplane uses the legacy Envoy DNS filter"); !ok {
		t.Errorf("expected an Envoy DNS filter blocker, got %+v", on.toModel("").Findings)
	}
}
