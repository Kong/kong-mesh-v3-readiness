package preflight

import (
	"strings"
	"testing"
)

// auditMesh audits a mock control plane whose only resource is the given Mesh
// (every other collection answers an empty list).
func auditMesh(t *testing.T, mesh map[string]any) Report {
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
		// EXC:FILE011:a-parse-error-makes-the-run-inconclusive — the status override covers the wrong-typed Mesh field case, which records a blocker yet reports status inconclusive.
		status string
		// EXC:FILE011:the-collector-merges-findings-and-keeps-the-first-detail — detailContains asserts the shared detail text a case depends on.
		detailContains string
		// EXC:FILE011:per-resource-values-live-in-the-example-annotation — exampleContains asserts the annotation a case's mesh carries.
		exampleContains string
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
			name:     "skipCreatingInitialPolicies with policy types",
			mesh:     map[string]any{"skipCreatingInitialPolicies": []any{"MeshRetry", "MeshTimeout"}},
			severity: "blocker", category: "Mesh object settings", title: "skipCreatingInitialPolicies on Mesh",
		},
		{
			name:     "skipCreatingInitialPolicies wildcard",
			mesh:     map[string]any{"skipCreatingInitialPolicies": []any{"*"}},
			severity: "blocker", category: "Mesh object settings", title: "skipCreatingInitialPolicies on Mesh",
		},
		{
			name:     "skipCreatingInitialPolicies empty list",
			mesh:     map[string]any{"skipCreatingInitialPolicies": []any{}},
			severity: "blocker", category: "Mesh object settings", title: "skipCreatingInitialPolicies on Mesh",
			detailContains:  "",
			exampleContains: "skipCreatingInitialPolicies: [] (empty list skips nothing)",
		},
		{
			name:     "skipCreatingInitialPolicies wrong type",
			mesh:     map[string]any{"skipCreatingInitialPolicies": "*"},
			severity: "blocker", category: "Unparseable resources", title: "Mesh spec could not be parsed",
			status: StatusInconclusive,
		},
		{
			name:     "non-RFC-1035 mesh name",
			mesh:     map[string]any{"name": "My_Mesh", "meshServices": map[string]any{"mode": "Exclusive"}},
			severity: "blocker", category: "Non-RFC-1035 names", title: "Mesh name is not a valid RFC-1035 DNS label",
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
			if tc.severity == "blocker" && m.Status != StatusBlockers && tc.status == "" {
				t.Errorf("status = %q, want %q", m.Status, StatusBlockers)
			}
			if tc.detailContains != "" && !strings.Contains(f.Detail, tc.detailContains) {
				t.Errorf("finding %q detail = %q, want it to contain %q", f.Title, f.Detail, tc.detailContains)
			}
			if tc.exampleContains != "" {
				found := false
				for _, ex := range f.Examples {
					if strings.Contains(ex, tc.exampleContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("finding %q examples %v, want one containing %q", f.Title, f.Examples, tc.exampleContains)
				}
			}
			if tc.status != "" && m.Status != tc.status {
				t.Errorf("status = %q, want %q", m.Status, tc.status)
			}
		})
	}
}

// TestCleanMeshHasNoIssues is the control: a fully migrated Mesh yields a clean
// report with no findings.
func TestCleanMeshHasNoIssues(t *testing.T) {
	m := auditMesh(t, map[string]any{"meshServices": map[string]any{"mode": "Exclusive"}})
	if m.Status != StatusClean {
		t.Errorf("status = %q, want %q", m.Status, StatusClean)
	}
	if len(m.Findings) != 0 {
		t.Errorf("expected no findings for a clean mesh, got %+v", m.Findings)
	}
}

// TestResourceNameUsesDisplayName checks the RFC-1035 rule against the logical
// name: a KDS-synced copy stored as "<name>-<hash>.<system-ns>" on a Kubernetes
// zone must be judged by its kuma.io/display-name, not by the stored name.
func TestResourceNameUsesDisplayName(t *testing.T) {
	const title = "MeshService name is not a valid RFC-1035 DNS label"
	ms := func(name string, labels map[string]any) map[string]any {
		return map[string]any{"type": "MeshService", "mesh": "default", "name": name, "labels": labels}
	}
	m := auditResponses(t, map[string]string{"/meshservices": listBody(t,
		ms("fraud-44cdzv5v8599f4x9.kuma-system", map[string]any{"kuma.io/display-name": "fraud", "kuma.io/origin": "global"}),
		ms("api.shop", map[string]any{"kuma.io/display-name": "api", "k8s.kuma.io/namespace": "shop"}),
		ms("legacy.api-888xx44854f4z282.kuma-system", map[string]any{"kuma.io/display-name": "legacy.api", "kuma.io/origin": "global"}),
		ms("dotted.name", nil),
	)})
	f, ok := findFinding(m, "blocker", "Non-RFC-1035 names", title)
	if !ok {
		t.Fatalf("invalid names not flagged\nfindings: %+v", m.Findings)
	}
	if f.Count != 2 {
		t.Errorf("count = %d, want 2 (synced copy of legacy.api and label-less dotted.name)\nexamples: %v", f.Count, f.Examples)
	}
	for _, ex := range f.Examples {
		if strings.Contains(ex, "fraud") || strings.Contains(ex, "api.shop") {
			t.Errorf("valid logical name flagged: %s", ex)
		}
	}
}

// TestSkipCreatingInitialPoliciesPerMeshList guards the finding against the
// collector's detail merging: two meshes carrying different lists must each
// name their own list in their example annotation, not share the first one.
func TestSkipCreatingInitialPoliciesPerMeshList(t *testing.T) {
	m := auditResponses(t, map[string]string{"/meshes": listBody(t,
		map[string]any{"name": "with-retry", "meshServices": map[string]any{"mode": "Exclusive"}, "skipCreatingInitialPolicies": []any{"MeshRetry"}},
		map[string]any{"name": "skip-all", "meshServices": map[string]any{"mode": "Exclusive"}, "skipCreatingInitialPolicies": []any{"*"}},
	)})
	f, ok := findFinding(m, "blocker", "Mesh object settings", "skipCreatingInitialPolicies on Mesh")
	if !ok {
		t.Fatalf("JSON report missing skipCreatingInitialPolicies finding\nfindings: %+v", m.Findings)
	}
	if f.Count != 2 {
		t.Errorf("count = %d, want 2\nexamples: %v", f.Count, f.Examples)
	}
	for _, want := range []string{"with-retry", "skip-all"} {
		wantAnnotation := " (skipCreatingInitialPolicies: "
		if want == "with-retry" {
			wantAnnotation += "MeshRetry)"
		} else {
			wantAnnotation += "*)"
		}
		matched := false
		for _, ex := range f.Examples {
			if strings.HasPrefix(ex, want) && strings.Contains(ex, wantAnnotation) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("examples %v missing %q with annotation %q", f.Examples, want, wantAnnotation)
		}
	}
	if strings.Contains(f.Detail, "MeshRetry") || strings.Contains(f.Detail, "skip-all") {
		t.Errorf("detail carries a per-mesh value: %q", f.Detail)
	}
}
