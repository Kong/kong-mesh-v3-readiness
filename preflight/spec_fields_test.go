package preflight

import (
	"strings"
	"testing"
)

func policyBody(t *testing.T, typ string, spec map[string]any, labels map[string]any) string {
	t.Helper()
	it := map[string]any{"type": typ, "mesh": "default", "name": "p-1", "spec": spec}
	if labels != nil {
		it["labels"] = labels
	}
	return listBody(t, it)
}

func displayNameLabels(name string) map[string]any {
	return map[string]any{"kuma.io/display-name": name}
}

// TestReferenceByName covers the 3.0 labels-only targetRef/backendRef: any ref to
// a real resource that names it instead of selecting by labels is flagged.
func TestReferenceByName(t *testing.T) {
	const title = "MeshTimeout references a resource by name"
	for _, tc := range []struct {
		name string
		spec map[string]any
		want bool
	}{
		{"top-level Dataplane by name", map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "name": "dp-1"}}, true},
		{"top-level Dataplane by labels", map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "labels": map[string]any{"app": "a"}}}, false},
		{"top-level Mesh", map[string]any{"targetRef": map[string]any{"kind": "Mesh", "mesh": "default"}}, false},
		{"to MeshService by name and namespace", map[string]any{
			"targetRef": map[string]any{"kind": "Mesh"},
			"to":        []any{map[string]any{"targetRef": map[string]any{"kind": "MeshService", "name": "backend", "namespace": "ns"}}},
		}, true},
		{"to MeshService by labels", map[string]any{
			"targetRef": map[string]any{"kind": "Mesh"},
			"to":        []any{map[string]any{"targetRef": map[string]any{"kind": "MeshService", "labels": displayNameLabels("backend")}}},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/meshtimeouts": policyBody(t, "MeshTimeout", tc.spec, nil)})
			if _, got := findFinding(m, "blocker", "Reference by name", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestRouteBackendRefs covers route backendRefs 3.0 cannot resolve: a subset kind
// (including in RequestMirror) and a ref by name.
func TestRouteBackendRefs(t *testing.T) {
	route := func(def map[string]any) map[string]any {
		return map[string]any{
			"targetRef": map[string]any{"kind": "Mesh"},
			"to": []any{map[string]any{
				"targetRef": map[string]any{"kind": "MeshService", "labels": displayNameLabels("backend")},
				"rules":     []any{map[string]any{"default": def}},
			}},
		}
	}
	subset := map[string]any{"kind": "MeshServiceSubset", "tags": map[string]any{"version": "v1"}}
	byLabels := map[string]any{"kind": "MeshService", "labels": displayNameLabels("backend"), "port": 8080}
	for _, tc := range []struct {
		name, path, typ, category, title string
		def                              map[string]any
	}{
		{
			"http subset backendRef", "/meshhttproutes", "MeshHTTPRoute", "Route backendRef", "MeshHTTPRoute backendRef kind=MeshServiceSubset",
			map[string]any{"backendRefs": []any{subset}},
		},
		{
			"http mirror to subset", "/meshhttproutes", "MeshHTTPRoute", "Route backendRef", "MeshHTTPRoute backendRef kind=MeshServiceSubset",
			map[string]any{"backendRefs": []any{byLabels}, "filters": []any{map[string]any{"type": "RequestMirror", "requestMirror": map[string]any{"backendRef": subset}}}},
		},
		{
			"tcp backendRef by name", "/meshtcproutes", "MeshTCPRoute", "Reference by name", "MeshTCPRoute references a resource by name",
			map[string]any{"backendRefs": []any{map[string]any{"kind": "MeshService", "name": "backend", "port": 8080}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{tc.path: policyBody(t, tc.typ, route(tc.def), nil)})
			if _, ok := findFinding(m, "blocker", tc.category, tc.title); !ok {
				t.Errorf("missing %q\nfindings: %+v", tc.title, m.Findings)
			}
		})
	}
	t.Run("labels-only backendRef is clean", func(t *testing.T) {
		m := auditResponses(t, map[string]string{"/meshhttproutes": policyBody(t, "MeshHTTPRoute", route(map[string]any{"backendRefs": []any{byLabels}}), nil)})
		for _, f := range m.Findings {
			if f.Category == "Route backendRef" || f.Category == "Reference by name" {
				t.Errorf("wrongly flagged %q", f.Title)
			}
		}
	})
	t.Run("one route counts once", func(t *testing.T) {
		spec := route(map[string]any{"backendRefs": []any{
			map[string]any{"kind": "MeshService", "name": "a", "weight": 50},
			map[string]any{"kind": "MeshService", "name": "b", "weight": 50},
			subset, subset,
		}})
		spec["to"].([]any)[0].(map[string]any)["targetRef"] = map[string]any{"kind": "MeshService", "name": "backend"}
		m := auditResponses(t, map[string]string{"/meshhttproutes": policyBody(t, "MeshHTTPRoute", spec, nil)})
		for _, w := range []struct{ category, title string }{
			{"Reference by name", "MeshHTTPRoute references a resource by name"},
			{"Route backendRef", "MeshHTTPRoute backendRef kind=MeshServiceSubset"},
		} {
			f, ok := findFinding(m, "blocker", w.category, w.title)
			if !ok || f.Count != 1 {
				t.Errorf("%q: found=%v count=%d, want count 1\nfindings: %+v", w.title, ok, f.Count, m.Findings)
			}
		}
	})
}

func TestMeshPassthroughDomainPort(t *testing.T) {
	const title = "MeshPassthrough Domain match has no port"
	for _, tc := range []struct {
		name  string
		match map[string]any
		want  bool
	}{
		{"domain without port", map[string]any{"type": "Domain", "value": "api.example.com", "protocol": "tls"}, true},
		{"domain with port", map[string]any{"type": "Domain", "value": "api.example.com", "port": 443, "protocol": "tls"}, false},
		{"wildcard domain without port", map[string]any{"type": "Domain", "value": "*.example.com", "protocol": "tls"}, false},
		{"IP without port", map[string]any{"type": "IP", "value": "10.0.0.1", "protocol": "tcp"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"default":   map[string]any{"passthroughMode": "Matched", "appendMatch": []any{tc.match}},
			}
			m := auditResponses(t, map[string]string{"/meshpassthroughs": policyBody(t, "MeshPassthrough", spec, nil)})
			if _, got := findFinding(m, "blocker", "MeshPassthrough", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestMeshPassthroughSameFilterChain mirrors the 3.0 duplicate-filter-chains
// validation (kumahq/kuma release-3.0 meshpassthrough testdata).
func TestMeshPassthroughSameFilterChain(t *testing.T) {
	const title = "MeshPassthrough matches produce the same filter chain"
	m := func(typ, value, protocol string, port int) map[string]any {
		match := map[string]any{"type": typ, "value": value, "protocol": protocol}
		if port != 0 {
			match["port"] = port
		}
		return match
	}
	for _, tc := range []struct {
		name    string
		matches []any
		want    string
	}{
		{"IP and its /32 CIDR", []any{m("IP", "10.0.0.1", "tcp", 8443), m("CIDR", "10.0.0.1/32", "tcp", 8443)}, `matches "10.0.0.1" and "10.0.0.1/32" produce the same filter chain for 10.0.0.1/32 on port 8443`},
		{"IP tcp and CIDR mysql", []any{m("IP", "10.0.0.1", "tcp", 3306), m("CIDR", "10.0.0.1/32", "mysql", 3306)}, "protocols tcp and mysql produce the same filter chain for 10.0.0.1/32 on port 3306"},
		{"tcp and mysql on one IP", []any{m("IP", "10.1.1.1", "tcp", 3306), m("IP", "10.1.1.1", "mysql", 3306)}, "protocols tcp and mysql produce the same filter chain"},
		{"CIDRs with the same canonical prefix", []any{m("CIDR", "10.0.0.1/24", "http", 8080), m("CIDR", "10.0.0.0/24", "grpc", 8080)}, "protocols http and grpc produce the same filter chain for 10.0.0.0/24 on port 8080"},
		{"IPv6 IP and /128 CIDR", []any{m("IP", "0:0:0:0:0:0:0:1", "tls", 443), m("CIDR", "::1/128", "tls", 443)}, "for ::1/128 on port 443"},
		{"http and grpc domains on one port are left to 2.14 validation", []any{m("Domain", "a.example.com", "http", 80), m("Domain", "b.example.com", "grpc", 80)}, ""},
		{"http domains on one port merge", []any{m("Domain", "a.example.com", "http", 80), m("Domain", "b.example.com", "http", 80)}, ""},
		{"tls domains get a chain each", []any{m("Domain", "a.example.com", "tls", 443), m("Domain", "b.example.com", "tls", 443)}, ""},
		{"same IP on different ports", []any{m("IP", "10.0.0.1", "tcp", 8443), m("CIDR", "10.0.0.1/32", "tcp", 9443)}, ""},
		{"tls and tcp on one IP", []any{m("IP", "10.0.0.1", "tls", 443), m("IP", "10.0.0.1", "tcp", 443)}, ""},
		{"IPv4-mapped IP stays IPv6", []any{m("IP", "::ffff:10.0.0.1", "tcp", 80), m("IP", "10.0.0.1", "tcp", 80)}, ""},
		{"wider CIDR is a different chain", []any{m("IP", "10.0.0.1", "tcp", 80), m("CIDR", "10.0.0.0/24", "tcp", 80)}, ""},
		{"invalid IP is skipped", []any{m("IP", "not-an-ip", "tcp", 80), m("IP", "not-an-ip", "mysql", 80)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"default":   map[string]any{"passthroughMode": "Matched", "appendMatch": tc.matches},
			}
			r := auditResponses(t, map[string]string{"/meshpassthroughs": policyBody(t, "MeshPassthrough", spec, nil)})
			f, got := findFinding(r, "blocker", "MeshPassthrough", title)
			if got != (tc.want != "") {
				t.Fatalf("flagged = %v, want %v\nfindings: %+v", got, tc.want != "", r.Findings)
			}
			if got && !strings.Contains(strings.Join(f.Examples, "\n"), tc.want) {
				t.Errorf("examples %q, want substring %q", f.Examples, tc.want)
			}
		})
	}
}

// TestServiceResourceSpecs covers the MeshService, MeshMultiZoneService and
// MeshExternalService fields 3.0 no longer reads or accepts.
func TestServiceResourceSpecs(t *testing.T) {
	for _, tc := range []struct {
		name, path, typ, category, title string
		spec, labels                     map[string]any
		want                             bool
	}{
		{
			"user dataplaneTags", "/meshservices", "MeshService", "MeshService selector", "MeshService selects proxies by dataplaneTags",
			map[string]any{"selector": map[string]any{"dataplaneTags": map[string]any{"app": "redis"}}},
			nil, true,
		},
		{
			"k8s-generated dataplaneTags", "/meshservices", "MeshService", "MeshService selector", "MeshService selects proxies by dataplaneTags",
			map[string]any{"selector": map[string]any{"dataplaneTags": map[string]any{"app": "redis"}}},
			map[string]any{"kuma.io/managed-by": "k8s-controller"},
			false,
		},
		{
			"universal-generated from kuma.io/service", "/meshservices", "MeshService", "MeshService selector", "Generated MeshService is keyed on kuma.io/service",
			map[string]any{"selector": map[string]any{"dataplaneTags": map[string]any{"kuma.io/service": "redis"}}},
			map[string]any{"kuma.io/managed-by": "meshservice-generator"},
			true,
		},
		{
			"dataplaneLabels", "/meshservices", "MeshService", "MeshService selector", "MeshService selects proxies by dataplaneTags",
			map[string]any{"selector": map[string]any{"dataplaneLabels": map[string]any{"matchLabels": map[string]any{"app": "redis"}}}},
			nil, false,
		},
		{
			"ServiceTag identity", "/meshservices", "MeshService", "MeshService identities", "MeshService declares a ServiceTag identity",
			map[string]any{"identities": []any{map[string]any{"type": "ServiceTag", "value": "redis"}}},
			nil, true,
		},
		{
			"k8s-generated ServiceTag identity", "/meshservices", "MeshService", "MeshService identities", "MeshService declares a ServiceTag identity",
			map[string]any{"identities": []any{map[string]any{"type": "ServiceTag", "value": "redis"}}},
			map[string]any{"kuma.io/managed-by": "k8s-controller"},
			false,
		},
		{
			"universal-generated ServiceTag identity", "/meshservices", "MeshService", "MeshService identities", "MeshService declares a ServiceTag identity",
			map[string]any{"identities": []any{map[string]any{"type": "ServiceTag", "value": "redis"}}},
			map[string]any{"kuma.io/managed-by": "meshservice-generator"},
			false,
		},
		{
			"kafka appProtocol", "/meshservices", "MeshService", "Service ports", "MeshService port uses an appProtocol 3.0 rejects",
			map[string]any{"ports": []any{map[string]any{"port": 9092, "appProtocol": "kafka"}}},
			nil, true,
		},
		{
			"supported appProtocols", "/meshservices", "MeshService", "Service ports", "MeshService port uses an appProtocol 3.0 rejects",
			map[string]any{"ports": []any{map[string]any{"port": 80, "appProtocol": "HTTP"}, map[string]any{"port": 81}}},
			nil, false,
		},
		{
			"multizone kafka appProtocol", "/meshmultizoneservices", "MeshMultiZoneService", "Service ports", "MeshMultiZoneService port uses an appProtocol 3.0 rejects",
			map[string]any{"ports": []any{map[string]any{"port": 9092, "appProtocol": "kafka"}}},
			nil, true,
		},
		{
			"external service old DataSource", "/meshexternalservices", "MeshExternalService", "MeshExternalService TLS", "MeshExternalService TLS uses the removed DataSource shape",
			map[string]any{"tls": map[string]any{"verification": map[string]any{"caCert": map[string]any{"inlineString": "pem"}}}},
			nil, true,
		},
		{
			"external service SecureDataSource", "/meshexternalservices", "MeshExternalService", "MeshExternalService TLS", "MeshExternalService TLS uses the removed DataSource shape",
			map[string]any{"tls": map[string]any{"verification": map[string]any{"caCert": map[string]any{"type": "Secret", "secretRef": map[string]any{"kind": "Secret", "name": "ca"}}}}},
			nil, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{tc.path: policyBody(t, tc.typ, tc.spec, tc.labels)})
			if _, got := findFinding(m, "blocker", tc.category, tc.title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}
