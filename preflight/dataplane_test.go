package preflight

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// auditDataplane audits a mock control plane whose only Dataplane is the given
// one (no meshes, every other collection empty), so dataplane findings stand
// alone in the report.
func auditDataplane(t *testing.T, dp map[string]any) Report {
	t.Helper()
	dp["type"] = "Dataplane"
	if dp["mesh"] == nil {
		dp["mesh"] = "default"
	}
	if dp["name"] == nil {
		dp["name"] = "dp-1"
	}
	return auditResponses(t, map[string]string{"/dataplanes": listBody(t, dp)})
}

// TestDataplaneDeprecatedFeatureReportedAsIssue checks that each deprecated
// Dataplane construct surfaces as the expected finding in the JSON report.
func TestDataplaneDeprecatedFeatureReportedAsIssue(t *testing.T) {
	cases := []struct {
		name     string
		dp       map[string]any
		severity string
		category string
		title    string
	}{
		{
			name: "reachableServices",
			dp: map[string]any{"networking": map[string]any{
				"transparentProxying": map[string]any{"reachableServices": []any{"svc-a", "svc-b"}},
			}},
			severity: "blocker", category: "reachableServices", title: "Dataplane uses reachableServices",
		},
		{
			name: "universal probes",
			dp: map[string]any{
				"labels": map[string]any{"kuma.io/env": "universal"},
				"probes": map[string]any{"port": 9000, "endpoints": []any{map[string]any{"inboundPort": 8080, "path": "/healthz"}}},
			},
			severity: "blocker", category: "Dataplane probes", title: "Dataplane has a probes section",
		},
		{
			name:     "universal missing workload label",
			dp:       map[string]any{"labels": map[string]any{"kuma.io/env": "universal"}},
			severity: "blocker", category: "Workload grouping", title: "Universal Dataplane missing kuma.io/workload label",
		},
		{
			name:     "unparseable spec",
			dp:       map[string]any{"networking": "this-should-be-an-object-not-a-string"},
			severity: "blocker", category: "Unparseable resources", title: "Dataplane spec could not be parsed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditDataplane(t, tc.dp)
			f, ok := findFinding(m, tc.severity, tc.category, tc.title)
			if !ok {
				t.Fatalf("JSON report missing %s finding %q (category %q)\nfindings: %+v", tc.severity, tc.title, tc.category, m.Findings)
			}
			if f.Count < 1 {
				t.Errorf("finding %q count = %d, want >= 1", tc.title, f.Count)
			}
			wantStatus := StatusBlockers
			if tc.category == "Unparseable resources" {
				wantStatus = StatusInconclusive
			}
			if tc.severity == "blocker" && m.Status != wantStatus {
				t.Errorf("status = %q, want %q", m.Status, wantStatus)
			}
		})
	}
}

// TestDataplaneProbesPerEnvironment confirms spec.probes is flagged with the
// environment's own remedy: on Kubernetes it marks a pod with virtual probes enabled, which
// 3.0 removes, so the fix is moving it to Application Probe Proxy.
func TestDataplaneProbesPerEnvironment(t *testing.T) {
	for _, tc := range []struct{ env, title, other string }{
		{"kubernetes", "Kubernetes pod has virtual probes enabled", "Dataplane has a probes section"},
		{"universal", "Dataplane has a probes section", "Kubernetes pod has virtual probes enabled"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			m := auditDataplane(t, map[string]any{
				"labels": map[string]any{"kuma.io/env": tc.env, "kuma.io/workload": "w"},
				"probes": map[string]any{"port": 9000},
			})
			if _, ok := findFinding(m, "blocker", "Dataplane probes", tc.title); !ok {
				t.Errorf("missing %q\nfindings: %+v", tc.title, m.Findings)
			}
			if _, ok := findFinding(m, "blocker", "Dataplane probes", tc.other); ok {
				t.Errorf("wrongly flagged %q", tc.other)
			}
		})
	}
}

// TestWorkloadLabelCheckIsUniversalOnly confirms the kuma.io/workload check fires
// only for Universal proxies missing the label: a Kubernetes proxy (label injected
// from the pod) and a Universal proxy that already carries it are both clean.
func TestWorkloadLabelCheckIsUniversalOnly(t *testing.T) {
	const title = "Universal Dataplane missing kuma.io/workload label"
	t.Run("kubernetes proxy is not flagged", func(t *testing.T) {
		m := auditDataplane(t, map[string]any{"labels": map[string]any{"kuma.io/env": "kubernetes"}})
		if _, ok := findFinding(m, "blocker", "Workload grouping", title); ok {
			t.Errorf("k8s dataplane wrongly flagged for a missing workload label\nfindings: %+v", m.Findings)
		}
	})
	t.Run("universal proxy with the label is not flagged", func(t *testing.T) {
		m := auditDataplane(t, map[string]any{"labels": map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "payments"}})
		if _, ok := findFinding(m, "blocker", "Workload grouping", title); ok {
			t.Errorf("labeled universal dataplane wrongly flagged\nfindings: %+v", m.Findings)
		}
	})
}

// TestCleanDataplaneHasNoIssues is the control: a migrated Dataplane yields a
// clean report with no findings.
func TestCleanDataplaneHasNoIssues(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"labels":     map[string]any{"kuma.io/workload": "dp-1"},
		"networking": map[string]any{"inbound": []any{map[string]any{"port": 8080}}},
	})
	if m.Status != StatusClean {
		t.Errorf("status = %q, want %q", m.Status, StatusClean)
	}
	if len(m.Findings) != 0 {
		t.Errorf("expected no findings for a clean dataplane, got %+v", m.Findings)
	}
}

// TestReachableBackendsDefault covers the 3.0 restrictOutbound=true default:
// only a transparent proxy whose reachableBackends is absent loses its outbounds.
// An explicit empty object already means "none" on 2.x, and a Universal proxy
// without a transparentProxying section never goes through reachable-backend
// filtering. Every k8s sidecar is transparent, section or not.
func TestReachableBackendsDefault(t *testing.T) {
	const title = "Transparent-proxy Dataplane has no reachableBackends"
	tp := func(fields map[string]any) map[string]any {
		return map[string]any{"transparentProxying": fields}
	}
	redirect := map[string]any{"redirectPortInbound": 15006, "redirectPortOutbound": 15001}
	withBackends := func(rb any) map[string]any {
		f := maps.Clone(redirect)
		f["reachableBackends"] = rb
		return f
	}
	inboundOnly := map[string]any{"inbound": []any{map[string]any{"port": 8080}}}
	backendRefOutbound := func(n map[string]any) map[string]any {
		n = maps.Clone(n)
		n["outbound"] = []any{map[string]any{"port": 10001, "backendRef": map[string]any{"kind": "MeshService", "name": "backend", "port": 80}}}
		return n
	}
	cases := []struct {
		name       string
		env        string
		labels     map[string]any
		networking map[string]any
		want       bool
	}{
		{"universal transparent proxy without reachableBackends", "universal", nil, tp(redirect), true},
		{"kubernetes transparent proxy without reachableBackends", "kubernetes", nil, tp(redirect), true},
		{"null reachableBackends counts as absent", "universal", nil, tp(withBackends(nil)), true},
		{"empty reachableBackends already restricts", "universal", nil, tp(withBackends(map[string]any{})), false},
		{"reachableBackends with refs", "kubernetes", nil, tp(withBackends(map[string]any{"refs": []any{map[string]any{"kind": "MeshService", "labels": map[string]any{"kuma.io/display-name": "backend"}}}})), false},
		{"no transparent proxy", "universal", nil, inboundOnly, false},
		// Tproxy config from the injector ConfigMap leaves the section nil on k8s.
		{"kubernetes sidecar without transparentProxying section", "kubernetes", nil, inboundOnly, true},
		{"kubernetes builtin gateway", "kubernetes", nil, map[string]any{"gateway": map[string]any{"type": "BUILTIN"}}, false},
		{"kubernetes zone proxy", "kubernetes", map[string]any{"kuma.io/listener-zoneingress": "enabled"}, inboundOnly, false},
		// Resolved backendRef outbounds win over reachableBackends in 3.0.
		{"universal transparent proxy with backendRef outbounds", "universal", nil, backendRefOutbound(tp(redirect)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			labels := map[string]any{"kuma.io/env": tc.env, "kuma.io/workload": "dp-1"}
			maps.Copy(labels, tc.labels)
			m := auditDataplane(t, map[string]any{
				"labels":     labels,
				"networking": tc.networking,
			})
			if _, got := findFinding(m, "blocker", "Dataplane networking", title); got != tc.want {
				t.Errorf("finding %q present = %v, want %v\nfindings: %+v", title, got, tc.want, m.Findings)
			}
		})
	}
}

// TestReachableBackendsDefaultAlreadyRestricted confirms a proxy is not flagged
// when its control plane already sets `defaults.restrictOutbound: true` on 2.x:
// it already runs with the 3.0 default, so the upgrade changes nothing for it.
func TestReachableBackendsDefaultAlreadyRestricted(t *testing.T) {
	const title = "Transparent-proxy Dataplane has no reachableBackends"
	tpDP := func(name, zone string) map[string]any {
		return map[string]any{
			"type": "Dataplane", "mesh": "default", "name": name,
			"labels":     map[string]any{"kuma.io/env": "kubernetes", "kuma.io/zone": zone},
			"networking": map[string]any{"transparentProxying": map[string]any{"redirectPortOutbound": 15001}},
		}
	}
	t.Run("zone control plane", func(t *testing.T) {
		m := auditResponses(t, map[string]string{
			"/config":     strings.Replace(readyConfigJSON, `"mode": "zone",`, `"mode": "zone", "defaults": {"restrictOutbound": true},`, 1),
			"/dataplanes": listBody(t, tpDP("dp-1", "east")),
		})
		if _, ok := findFinding(m, "blocker", "Dataplane networking", title); ok {
			t.Errorf("proxy flagged although its CP already restricts outbound\nfindings: %+v", m.Findings)
		}
	})
	t.Run("global flags only zones not yet restricted", func(t *testing.T) {
		zoneCfg := func(restrict bool) string {
			return fmt.Sprintf(`{"mode": "zone", "environment": "kubernetes", "defaults": {"restrictOutbound": %t}}`, restrict)
		}
		zone := func(name string, restrict bool) map[string]any {
			return map[string]any{
				"type": "ZoneOverview", "name": name,
				"zoneInsight": map[string]any{"subscriptions": []any{map[string]any{"config": zoneCfg(restrict)}}},
			}
		}
		m := auditResponses(t, map[string]string{
			"/config":         `{"mode": "global", "environment": "universal"}`,
			"/zones+insights": listBody(t, zone("east", true), zone("west", false)),
			"/dataplanes":     listBody(t, tpDP("dp-east", "east"), tpDP("dp-west", "west")),
		})
		f, ok := findFinding(m, "blocker", "Dataplane networking", title)
		if !ok {
			t.Fatalf("unrestricted zone's proxy not flagged\nfindings: %+v", m.Findings)
		}
		if want := []string{"default/dp-west [zone:west]"}; !slices.Equal(f.Examples, want) {
			t.Errorf("flagged = %v, want %v", f.Examples, want)
		}
	})
}
