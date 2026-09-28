package preflight

import "testing"

// TestProducerPolicyRole covers 3.0's stricter producer rule: every to[] item
// must pin one MeshService/MeshHTTPRoute of the policy's own namespace and zone
// by exactly display-name, namespace and zone.
func TestProducerPolicyRole(t *testing.T) {
	const title = "MeshTimeout stops being a producer policy"
	role := map[string]any{"kuma.io/policy-role": "producer", "k8s.kuma.io/namespace": "ns", "kuma.io/zone": "east"}
	to := func(kind string, labels map[string]any) map[string]any {
		return map[string]any{
			"targetRef": map[string]any{"kind": "Mesh"},
			"to":        []any{map[string]any{"targetRef": map[string]any{"kind": kind, "labels": labels}}},
		}
	}
	pinned := map[string]any{"kuma.io/display-name": "backend", "k8s.kuma.io/namespace": "ns", "kuma.io/zone": "east"}
	for _, tc := range []struct {
		name   string
		spec   map[string]any
		labels map[string]any
		want   bool
	}{
		{"pinned to own namespace and zone", to("MeshService", pinned), role, false},
		{"display-name only", to("MeshService", map[string]any{"kuma.io/display-name": "backend"}), role, true},
		{"other namespace", to("MeshService", map[string]any{"kuma.io/display-name": "backend", "k8s.kuma.io/namespace": "other", "kuma.io/zone": "east"}), role, true},
		{"extra label", to("MeshHTTPRoute", map[string]any{"kuma.io/display-name": "r", "k8s.kuma.io/namespace": "ns", "kuma.io/zone": "east", "app": "a"}), role, true},
		{"by name", map[string]any{
			"targetRef": map[string]any{"kind": "Mesh"},
			"to":        []any{map[string]any{"targetRef": map[string]any{"kind": "MeshService", "name": "backend"}}},
		}, role, true},
		{"other zone", to("MeshService", map[string]any{"kuma.io/display-name": "backend", "k8s.kuma.io/namespace": "ns", "kuma.io/zone": "west"}), role, true},
		{"policy without zone", to("MeshService", map[string]any{"kuma.io/display-name": "backend", "k8s.kuma.io/namespace": "ns", "kuma.io/zone": ""}), map[string]any{"kuma.io/policy-role": "producer", "k8s.kuma.io/namespace": "ns"}, true},
		{"MeshExternalService item", to("MeshExternalService", pinned), role, true},
		{"mixed items", map[string]any{
			"targetRef": map[string]any{"kind": "Mesh"},
			"to": []any{
				map[string]any{"targetRef": map[string]any{"kind": "MeshService", "labels": pinned}},
				map[string]any{"targetRef": map[string]any{"kind": "Mesh"}},
			},
		}, role, true},
		{"consumer policy", to("MeshService", map[string]any{"kuma.io/display-name": "backend"}), map[string]any{"kuma.io/policy-role": "consumer"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/meshtimeouts": policyBody(t, "MeshTimeout", tc.spec, tc.labels)})
			if _, got := findFinding(m, "blocker", "Policy role", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestExternalServiceIdentity covers 3.0's MeshIdentity requirement for
// MeshExternalService clusters, and that an unreadable MeshIdentity list is a
// coverage gap rather than "no identity".
func TestExternalServiceIdentity(t *testing.T) {
	const title = "Mesh has MeshExternalServices but no MeshIdentity"
	mes := policyBody(t, "MeshExternalService", map[string]any{}, nil)
	identity := policyBody(t, "MeshIdentity", map[string]any{}, nil)
	for _, tc := range []struct {
		name      string
		responses map[string]string
		notFound  []string
		want      bool
	}{
		{"no identity", map[string]string{"/meshexternalservices": mes}, nil, true},
		{"identity present", map[string]string{"/meshexternalservices": mes, "/meshidentities": identity}, nil, false},
		{"identity not served", map[string]string{"/meshexternalservices": mes}, []string{"/meshidentities"}, true},
		{"no external services", map[string]string{}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditWithNotFound(t, tc.responses, tc.notFound...)
			if _, got := findFinding(m, "blocker", "MeshIdentity coverage", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
	t.Run("unreadable identity list is a gap", func(t *testing.T) {
		m := auditResponsesFunc(t, func(path string) (string, int, bool) {
			switch path {
			case "/meshexternalservices":
				return mes, 200, true
			case "/meshidentities":
				return `{}`, 500, true
			}
			return "", 0, false
		})
		if _, ok := findFinding(m, "blocker", "MeshIdentity coverage", title); ok {
			t.Errorf("flagged despite an unreadable MeshIdentity list\nfindings: %+v", m.Findings)
		}
		if m.Status != StatusInconclusive {
			t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
		}
	})
}
