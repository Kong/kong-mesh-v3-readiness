package main

import "testing"

// auditDataplane audits a mock control plane whose only Dataplane is the given
// one (no meshes, every other collection empty), so dataplane findings stand
// alone in the report.
func auditDataplane(t *testing.T, dp map[string]any) reportModel {
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
			name: "gateway section",
			dp: map[string]any{"networking": map[string]any{
				"gateway": map[string]any{"type": "BUILTIN", "tags": map[string]any{"kuma.io/service": "gw"}},
			}},
			severity: "blocker", category: "Gateway in Dataplane", title: "Dataplane has a gateway section",
		},
		{
			name: "universal probes",
			dp: map[string]any{
				"labels": map[string]any{"kuma.io/env": "universal"},
				"probes": map[string]any{"port": 9000, "endpoints": []any{map[string]any{"inboundPort": 8080, "path": "/healthz"}}},
			},
			severity: "warning", category: "Dataplane probes", title: "Dataplane has a probes section",
		},
		{
			name:     "unparseable spec",
			dp:       map[string]any{"networking": "this-should-be-an-object-not-a-string"},
			severity: "warning", category: "Unparseable resources", title: "Dataplane spec could not be parsed",
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
			if tc.severity == "blocker" && m.Status != statusBlockers {
				t.Errorf("status = %q, want %q", m.Status, statusBlockers)
			}
		})
	}
}

// TestDataplaneProbesIgnoredOnKubernetes confirms the probes warning is
// Universal-only: on Kubernetes probes are derived from the pod and need no
// action, so they must not be flagged.
func TestDataplaneProbesIgnoredOnKubernetes(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"labels": map[string]any{"kuma.io/env": "kubernetes"},
		"probes": map[string]any{"port": 9000},
	})
	if _, ok := findFinding(m, "warning", "Dataplane probes", "Dataplane has a probes section"); ok {
		t.Errorf("probes on a Kubernetes dataplane must not be flagged\nfindings: %+v", m.Findings)
	}
	if m.Status != statusClean {
		t.Errorf("status = %q, want %q", m.Status, statusClean)
	}
}

// TestCleanDataplaneHasNoIssues is the control: a migrated Dataplane yields a
// clean report with no findings.
func TestCleanDataplaneHasNoIssues(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"networking": map[string]any{"inbound": []any{map[string]any{"port": 8080}}},
	})
	if m.Status != statusClean {
		t.Errorf("status = %q, want %q", m.Status, statusClean)
	}
	if len(m.Findings) != 0 {
		t.Errorf("expected no findings for a clean dataplane, got %+v", m.Findings)
	}
}
