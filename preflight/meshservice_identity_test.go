package preflight

import "testing"

// TestGeneratedServiceTagIdentity flags a generated MeshService that still lists a
// ServiceTag identity in a mesh without Mesh mTLS, which 3.0 Kubernetes zones
// refuse when they sync it.
func TestGeneratedServiceTagIdentity(t *testing.T) {
	const (
		generated   = "Generated MeshService keeps a ServiceTag identity without Mesh mTLS"
		handWritten = "MeshService declares a ServiceTag identity"
	)
	mesh := func(mtls bool) map[string]any {
		m := map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}}
		if mtls {
			m["mtls"] = map[string]any{"enabledBackend": "ca-1", "backends": []any{map[string]any{"name": "ca-1", "type": "builtin"}}}
		}
		return m
	}
	ms := func(labels map[string]any, types ...string) map[string]any {
		var ids []any
		for _, typ := range types {
			ids = append(ids, map[string]any{"type": typ, "value": "backend"})
		}
		return map[string]any{
			"type": "MeshService", "mesh": "default", "name": "backend", "labels": labels,
			"spec": map[string]any{"identities": ids},
		}
	}
	managed := map[string]any{"kuma.io/managed-by": "k8s-controller", "kuma.io/zone": "zone-1"}
	for _, tc := range []struct {
		name string
		mtls bool
		ms   map[string]any
		want string
	}{
		{"generated, mesh without mtls", false, ms(managed, "ServiceTag", "SpiffeID"), generated},
		{"generated, mesh with mtls", true, ms(managed, "ServiceTag", "SpiffeID"), ""},
		{"generated, spiffe only", false, ms(managed, "SpiffeID"), ""},
		{"hand-written", false, ms(nil, "ServiceTag"), handWritten},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/meshes":       listBody(t, mesh(tc.mtls)),
				"/meshservices": listBody(t, tc.ms),
			})
			for _, title := range []string{generated, handWritten} {
				_, got := findFinding(m, "blocker", "MeshService identities", title)
				if want := title == tc.want; got != want {
					t.Errorf("%q flagged = %v, want %v\nfindings: %+v", title, got, want, m.Findings)
				}
			}
		})
	}
}
