package main

import "testing"

// auditMesh audits a mock control plane whose only resource is the given Mesh
// (every other collection answers an empty list).
func auditMesh(t *testing.T, mesh map[string]any) reportModel {
	t.Helper()
	mesh["type"] = "Mesh"
	if mesh["name"] == nil {
		mesh["name"] = "default"
	}
	return auditResponses(t, map[string]string{"/meshes": listBody(t, mesh)})
}

// TestMeshDeprecatedFeatureReportedAsIssue checks that each deprecated Mesh
// setting surfaces as the expected finding in the JSON report.
func TestMeshDeprecatedFeatureReportedAsIssue(t *testing.T) {
	cases := []struct {
		name     string
		mesh     map[string]any
		severity string
		category string
		title    string
	}{
		{
			name:     "inline mTLS",
			mesh:     map[string]any{"mtls": map[string]any{"enabledBackend": "ca-1"}},
			severity: "blocker", category: "Mesh object settings", title: "Inline mTLS on Mesh",
		},
		{
			name:     "outbound passthrough",
			mesh:     map[string]any{"networking": map[string]any{"outbound": map[string]any{"passthrough": true}}},
			severity: "blocker", category: "Mesh object settings", title: "Passthrough on Mesh",
		},
		{
			name:     "routing.zoneEgress",
			mesh:     map[string]any{"routing": map[string]any{"zoneEgress": true}},
			severity: "blocker", category: "Mesh object settings", title: "routing.zoneEgress on Mesh",
		},
		{
			name:     "routing.defaultForbidMeshExternalServiceAccess",
			mesh:     map[string]any{"routing": map[string]any{"defaultForbidMeshExternalServiceAccess": true}},
			severity: "blocker", category: "Mesh object settings", title: "defaultForbidMeshExternalServiceAccess on Mesh",
		},
		{
			name:     "routing.localityAwareLoadBalancing",
			mesh:     map[string]any{"routing": map[string]any{"localityAwareLoadBalancing": true}},
			severity: "blocker", category: "Mesh object settings", title: "localityAwareLoadBalancing on Mesh",
		},
		{
			name:     "inline metrics",
			mesh:     map[string]any{"metrics": map[string]any{"enabledBackend": "prom", "backends": []any{map[string]any{"type": "prometheus"}}}},
			severity: "blocker", category: "Mesh object settings", title: "Inline metrics on Mesh",
		},
		{
			name:     "inline tracing",
			mesh:     map[string]any{"tracing": map[string]any{"backends": []any{map[string]any{"type": "zipkin"}}}},
			severity: "blocker", category: "Mesh object settings", title: "Inline tracing on Mesh",
		},
		{
			name:     "inline logging",
			mesh:     map[string]any{"logging": map[string]any{"backends": []any{map[string]any{"type": "file"}}}},
			severity: "blocker", category: "Mesh object settings", title: "Inline logging on Mesh",
		},
		{
			name:     "membership constraints",
			mesh:     map[string]any{"constraints": map[string]any{"dataplaneProxy": map[string]any{"requirements": []any{}}}},
			severity: "blocker", category: "Mesh object settings", title: "Mesh membership constraints",
		},
		{
			name:     "meshServices.mode not Exclusive",
			mesh:     map[string]any{"meshServices": map[string]any{"mode": "Everywhere"}},
			severity: "blocker", category: "MeshService mode", title: "meshServices.mode is not Exclusive",
		},
		{
			name:     "meshServices absent defaults to Disabled",
			mesh:     map[string]any{},
			severity: "blocker", category: "MeshService mode", title: "meshServices.mode is not Exclusive",
		},
		{
			name:     "non-RFC-1035 mesh name",
			mesh:     map[string]any{"name": "My_Mesh", "meshServices": map[string]any{"mode": "Exclusive"}},
			severity: "warning", category: "Non-RFC-1035 names", title: "Mesh name is not a valid RFC-1035 DNS label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditMesh(t, tc.mesh)
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

// TestCleanMeshHasNoIssues is the control: a fully migrated Mesh yields a clean
// report with no findings.
func TestCleanMeshHasNoIssues(t *testing.T) {
	m := auditMesh(t, map[string]any{"meshServices": map[string]any{"mode": "Exclusive"}})
	if m.Status != statusClean {
		t.Errorf("status = %q, want %q", m.Status, statusClean)
	}
	if len(m.Findings) != 0 {
		t.Errorf("expected no findings for a clean mesh, got %+v", m.Findings)
	}
}
