package preflight

import "testing"

// TestMeshServiceServiceTagIdentity flags a hand-written MeshService that lists a
// ServiceTag identity, which 3.0 rejects on write. A generated MeshService is
// rewritten by its zone CP, so it is never flagged here.
func TestMeshServiceServiceTagIdentity(t *testing.T) {
	const handWritten = "MeshService declares a ServiceTag identity"

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
		ms   map[string]any
		want string
	}{
		{"hand-written", ms(nil, "ServiceTag"), handWritten},
		{"generated, service tag", ms(managed, "ServiceTag", "SpiffeID"), ""},
		{"generated, spiffe only", ms(managed, "SpiffeID"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/meshservices": listBody(t, tc.ms),
			})
			_, got := findFinding(m, "blocker", "MeshService identities", handWritten)
			if want := tc.want == handWritten; got != want {
				t.Errorf("%q flagged = %v, want %v\nfindings: %+v", handWritten, got, want, m.Findings)
			}
		})
	}
}
