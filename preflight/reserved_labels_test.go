package preflight

import (
	"slices"
	"testing"
)

// TestReservedLabelsOnWrite covers the 3.0 rejection of unknown kuma.io/ and
// k8s.kuma.io/ labels: flagged on user-authored resources, not on labels the
// 2.14 control plane stamps itself or on CP-written (k8s, generated) resources.
func TestReservedLabelsOnWrite(t *testing.T) {
	for _, tc := range []struct {
		name, path, typ, title string
		labels                 map[string]any
		want                   []string
	}{
		{
			"policy with kuma.io/service", "/meshtimeouts", "MeshTimeout", "MeshTimeout carries a reserved label 3.0 rejects",
			map[string]any{"kuma.io/service": "web", "kuma.io/zone": "east", "app": "web"},
			[]string{"default/p-1 [zone:east] (kuma.io/service)"},
		},
		{
			"policy with only registry labels", "/meshtimeouts", "MeshTimeout", "MeshTimeout carries a reserved label 3.0 rejects",
			map[string]any{"kuma.io/origin": "zone", "kuma.io/policy-role": "producer", "k8s.kuma.io/namespace": "ns"},
			nil,
		},
		{
			"universal dataplane", "/dataplanes", "Dataplane", "Dataplane carries a reserved label 3.0 rejects",
			map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "w", "kuma.io/protocol": "http", "k8s.kuma.io/service-port": "80", "kuma.io/proxy-type": "sidecar"},
			[]string{"default/p-1 (k8s.kuma.io/service-port, kuma.io/protocol)"},
		},
		{
			"kubernetes dataplane", "/dataplanes", "Dataplane", "Dataplane carries a reserved label 3.0 rejects",
			map[string]any{"kuma.io/env": "kubernetes", "kuma.io/instance": "x"},
			nil,
		},
		{
			"user meshservice", "/meshservices", "MeshService", "MeshService carries a reserved label 3.0 rejects",
			map[string]any{"kuma.io/service": "web"},
			[]string{"default/p-1 (kuma.io/service)"},
		},
		{
			"generated meshservice", "/meshservices", "MeshService", "MeshService carries a reserved label 3.0 rejects",
			map[string]any{"kuma.io/managed-by": "k8s-controller", "kuma.io/service": "web"},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{tc.path: policyBody(t, tc.typ, map[string]any{}, tc.labels)})
			f, ok := findFinding(m, "blocker", "Reserved labels", tc.title)
			if ok != (tc.want != nil) || (ok && !slices.Equal(f.Examples, tc.want)) {
				t.Errorf("finding = %+v (found %v), want examples %v\nfindings: %+v", f, ok, tc.want, m.Findings)
			}
		})
	}
}

// TestSelectorOnRemovedLabel covers selectors keyed on reserved labels 3.0 no
// longer sets on Dataplanes and services, in every place a selector lives.
func TestSelectorOnRemovedLabel(t *testing.T) {
	svc := map[string]any{"kuma.io/service": "web"}
	for _, tc := range []struct {
		name, path, typ string
		spec            map[string]any
		want            bool
	}{
		{
			"top-level targetRef", "/meshtimeouts", "MeshTimeout",
			map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "labels": map[string]any{"kuma.io/proxy-type": "gateway"}}},
			true,
		},
		{
			"to targetRef", "/meshtimeouts", "MeshTimeout",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "to": []any{map[string]any{"targetRef": map[string]any{"kind": "MeshService", "labels": svc}}}},
			true,
		},
		{
			"route backendRef", "/meshhttproutes", "MeshHTTPRoute",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "to": []any{map[string]any{
				"targetRef": map[string]any{"kind": "MeshService", "labels": displayNameLabels("web")},
				"rules":     []any{map[string]any{"default": map[string]any{"backendRefs": []any{map[string]any{"kind": "MeshService", "labels": svc}}}}},
			}}},
			true,
		},
		{
			"affinity tag", "/meshloadbalancingstrategies", "MeshLoadBalancingStrategy",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "to": []any{map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"default":   map[string]any{"localityAwareness": map[string]any{"localZone": map[string]any{"affinityTags": []any{map[string]any{"key": "kuma.io/service"}}}}},
			}}},
			true,
		},
		{
			"meshservice dataplaneLabels", "/meshservices", "MeshService",
			map[string]any{"selector": map[string]any{"dataplaneLabels": map[string]any{"matchLabels": svc}}},
			true,
		},
		{
			"route RequestMirror backendRef", "/meshhttproutes", "MeshHTTPRoute",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "to": []any{map[string]any{
				"targetRef": map[string]any{"kind": "MeshService", "labels": displayNameLabels("web")},
				"rules": []any{map[string]any{"default": map[string]any{"filters": []any{map[string]any{
					"type": "RequestMirror", "requestMirror": map[string]any{"backendRef": map[string]any{"kind": "MeshService", "labels": svc}},
				}}}}},
			}}},
			true,
		},
		{
			"tcp route backendRef", "/meshtcproutes", "MeshTCPRoute",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "to": []any{map[string]any{
				"targetRef": map[string]any{"kind": "MeshService", "labels": displayNameLabels("web")},
				"rules":     []any{map[string]any{"default": map[string]any{"backendRefs": []any{map[string]any{"kind": "MeshService", "labels": svc}}}}},
			}}},
			true,
		},
		{
			"proxy-ready selector", "/meshtimeouts", "MeshTimeout",
			map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "labels": map[string]any{"kuma.io/proxy-ready": "true"}}},
			true,
		},
		{
			"meshmultizoneservice meshService selector", "/meshmultizoneservices", "MeshMultiZoneService",
			map[string]any{"selector": map[string]any{"meshService": map[string]any{"matchLabels": svc}}},
			true,
		},
		{
			"meshmultizoneservice registry selector", "/meshmultizoneservices", "MeshMultiZoneService",
			map[string]any{"selector": map[string]any{"meshService": map[string]any{"matchLabels": map[string]any{"kuma.io/display-name": "web", "k8s.kuma.io/namespace": "ns"}}}},
			false,
		},
		{
			"registry and custom labels", "/meshtimeouts", "MeshTimeout",
			map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "labels": map[string]any{"kuma.io/workload": "w", "k8s.kuma.io/namespace": "ns", "app": "web"}}},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{tc.path: policyBody(t, tc.typ, tc.spec, nil)})
			if _, got := findFinding(m, "blocker", "Reserved labels", tc.typ+" selects on a label 3.0 no longer sets"); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}
