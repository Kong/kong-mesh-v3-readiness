package preflight

import (
	"strings"
	"testing"
)

// allFeatures is what a 3.0-ready 2.14 transparent-proxy sidecar advertises.
var allFeatures = []any{
	featureUnifiedNaming, featureEmbeddedDNS, featureDeltaGRPC, featureReusePort,
	featureStrictInboundPorts, featureOtelViaKumaDp, featureTransparentProxyInDPMeta,
}

func without(feats []any, drop string) []any {
	var out []any
	for _, f := range feats {
		if f != drop {
			out = append(out, f)
		}
	}
	return out
}

func featureInsight(labels map[string]any, features []any) map[string]any {
	return map[string]any{
		"type": "DataplaneOverview", "mesh": "default", "name": "dp-1", "labels": labels,
		"dataplane": map[string]any{"networking": map[string]any{"transparentProxying": map[string]any{}}},
		"dataplaneInsight": map[string]any{
			"subscriptions": []any{map[string]any{"version": map[string]any{"kumaDp": map[string]any{"version": "2.14.5", "kumaCpCompatible": true}}}},
			"metadata":      map[string]any{"features": features},
		},
	}
}

func TestDataplaneFeatures(t *testing.T) {
	const (
		sotw     = "Dataplane uses state-of-the-world xDS"
		reuse    = "Dataplane opts out of SO_REUSEPORT or strict inbound ports"
		otel     = "Dataplane exports OpenTelemetry directly"
		legacyTP = "Pod is configured through legacy transparent proxy annotations"
	)
	cniConfig := strings.Replace(readyConfigJSON, `"unifiedResourceNamingEnabled": true,`,
		`"unifiedResourceNamingEnabled": true, "cniEnabled": true, "transparentProxyConfigMap": "kuma-transparent-proxy-config",`, 1)
	k8s := map[string]any{"kuma.io/env": "kubernetes"}
	for _, tc := range []struct {
		name     string
		config   string
		labels   map[string]any
		features []any
		want     []string
	}{
		{"ready proxy", cniConfig, k8s, allFeatures, nil},
		{"sotw", readyConfigJSON, k8s, without(allFeatures, featureDeltaGRPC), []string{sotw}},
		{"reuse port off", readyConfigJSON, k8s, without(allFeatures, featureReusePort), []string{reuse}},
		{"strict inbound ports off", readyConfigJSON, k8s, without(allFeatures, featureStrictInboundPorts), []string{reuse}},
		{"otel pipe off", readyConfigJSON, k8s, without(allFeatures, featureOtelViaKumaDp), []string{otel}},
		{"legacy tproxy with cni", cniConfig, k8s, without(allFeatures, featureTransparentProxyInDPMeta), []string{legacyTP}},
		{"legacy tproxy without cni", readyConfigJSON, k8s, without(allFeatures, featureTransparentProxyInDPMeta), nil},
		{"zone proxy has no tproxy", cniConfig, map[string]any{"kuma.io/env": "kubernetes", "kuma.io/listener-zoneegress": "enabled"}, without(allFeatures, featureTransparentProxyInDPMeta), nil},
		{"universal proxy without tproxy", cniConfig, map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "w"}, without(allFeatures, featureTransparentProxyInDPMeta), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/config":              tc.config,
				"/dataplanes+insights": listBody(t, featureInsight(tc.labels, tc.features)),
			})
			for _, title := range []string{sotw, reuse, otel, legacyTP} {
				_, got := findFinding(m, "blocker", "Dataplane features", title)
				want := false
				for _, w := range tc.want {
					want = want || w == title
				}
				if got != want {
					t.Errorf("%q flagged = %v, want %v\nfindings: %+v", title, got, want, m.Findings)
				}
			}
		})
	}
}

func TestCNIWithoutTransparentProxyConfigMap(t *testing.T) {
	const title = "CNI configures pods from legacy transparent proxy annotations"
	for _, tc := range []struct {
		name string
		env  string
		cm   string
		want bool
	}{
		{"cni on legacy annotations", "kubernetes", "", true},
		{"cni on configmap", "kubernetes", "kuma-transparent-proxy-config", false},
		{"universal ignores injector", "universal", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := goodK8sConfig()
			c.Environment = tc.env
			c.Runtime.Kubernetes.Injector.CNIEnabled = true
			c.Runtime.Kubernetes.Injector.TransparentProxyConfigMap = tc.cm
			a := &auditor{rep: &collector{}}
			a.addCPConfigFindings(c, "")
			got := false
			for _, f := range a.rep.findings {
				got = got || f.title == title
			}
			if got != tc.want {
				t.Errorf("flagged = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOutboundBackendRefByName(t *testing.T) {
	const title = "Dataplane outbound backendRef selects by name"
	for _, tc := range []struct {
		name       string
		backendRef map[string]any
		want       bool
	}{
		{"by name", map[string]any{"kind": "MeshService", "name": "backend", "port": 80}, true},
		{"by labels", map[string]any{"kind": "MeshService", "labels": map[string]any{"kuma.io/display-name": "backend", "kuma.io/zone": "zone-1"}, "port": 80}, false},
		{"MeshExternalService by name", map[string]any{"kind": "MeshExternalService", "name": "httpbin", "port": 80}, false},
		{"MeshMultiZoneService by name", map[string]any{"kind": "MeshMultiZoneService", "name": "backend", "port": 80}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditDataplane(t, map[string]any{
				"labels": map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "w"},
				"networking": map[string]any{
					"address":  "10.0.0.1",
					"outbound": []any{map[string]any{"port": 10001, "backendRef": tc.backendRef}},
				},
			})
			if _, got := findFinding(m, "blocker", "Dataplane networking", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

func TestMeshHTTPRouteEmptyBackendRefs(t *testing.T) {
	const title = "MeshHTTPRoute rule has an empty backendRefs list"
	route := func(def map[string]any) map[string]any {
		return map[string]any{
			"type": "MeshHTTPRoute", "mesh": "default", "name": "route-1",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{map[string]any{
					"targetRef": map[string]any{"kind": "MeshService", "labels": map[string]any{"kuma.io/display-name": "backend"}},
					"rules":     []any{map[string]any{"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/"}}}, "default": def}},
				}},
			},
		}
	}
	for _, tc := range []struct {
		name string
		def  map[string]any
		want bool
	}{
		{"explicit empty list", map[string]any{"backendRefs": []any{}}, true},
		{"absent", map[string]any{}, false},
		{"populated", map[string]any{"backendRefs": []any{map[string]any{"kind": "MeshService", "labels": map[string]any{"kuma.io/display-name": "backend"}, "port": 80}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/meshhttproutes": listBody(t, route(tc.def))})
			if _, got := findFinding(m, "blocker", "MeshHTTPRoute routing", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

func TestZoneOriginMeshExternalService(t *testing.T) {
	const title = "Zone-origin MeshExternalService is reached through its own zone"
	mes := func(labels map[string]any) map[string]any {
		return map[string]any{
			"type": "MeshExternalService", "mesh": "default", "name": "httpbin", "labels": labels,
			"spec": map[string]any{"match": map[string]any{"type": "HostnameGenerator", "port": 80, "protocol": "http"}},
		}
	}
	zoneOrigin := map[string]any{"kuma.io/origin": "zone", "kuma.io/zone": "east"}
	global := func(zones []string) map[string]string {
		zoneItems := make([]map[string]any, 0, len(zones))
		dpItems := make([]map[string]any, 0, len(zones))
		for _, z := range zones {
			zoneItems = append(zoneItems, map[string]any{"type": "ZoneOverview", "name": z})
			dpItems = append(dpItems, universalDP("default", "dp-"+z, z))
		}
		return map[string]string{
			"/config":         `{"mode": "global", "environment": "universal"}`,
			"/meshes":         listBody(t, map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}}),
			"/zones+insights": listBody(t, zoneItems...),
			"/dataplanes":     listBody(t, dpItems...),
		}
	}
	withMES := func(zones []string, labels map[string]any) map[string]string {
		r := global(zones)
		r["/meshexternalservices"] = listBody(t, mes(labels))
		return r
	}
	for _, tc := range []struct {
		name      string
		responses map[string]string
		want      bool
	}{
		{
			name:      "multizone global with the mesh spanning zones",
			responses: withMES([]string{"east", "west"}, zoneOrigin),
			want:      true,
		},
		{
			name: "unfederated zone has no client elsewhere",
			responses: map[string]string{
				"/config":               `{"mode": "zone", "environment": "universal"}`,
				"/meshexternalservices": listBody(t, mes(map[string]any{"kuma.io/origin": "zone", "kuma.io/zone": "default"})),
			},
			want: false,
		},
		{
			name:      "single-zone global has no cross-zone traffic",
			responses: withMES([]string{"east"}, zoneOrigin),
			want:      false,
		},
		{
			name: "multizone global but the mesh is local to one zone",
			responses: func() map[string]string {
				r := withMES([]string{"east", "west"}, zoneOrigin)
				r["/dataplanes"] = listBody(t, universalDP("default", "dp-e", "east"))
				return r
			}(),
			want: false,
		},
		{
			name:      "global-origin MeshExternalService is not zone-routed",
			responses: withMES([]string{"east", "west"}, map[string]any{"kuma.io/origin": "global"}),
			want:      false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, tc.responses)
			if _, got := findFinding(m, "blocker", "MeshExternalService routing", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

func TestDataplaneOlderThanTargetMinor(t *testing.T) {
	const title = "Dataplane runs kuma-dp older than 2.14"
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"2.13.4", true},
		{"2.12.0", true},
		{"2.14.0", false},
		{"2.14.5", false},
		{"not-a-version", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			ins := featureInsight(map[string]any{"kuma.io/env": "kubernetes"}, allFeatures)
			ins["dataplaneInsight"].(map[string]any)["subscriptions"] = []any{map[string]any{"version": map[string]any{"kumaDp": map[string]any{"version": tc.version, "kumaCpCompatible": true}}}}
			m := auditResponses(t, map[string]string{
				"/config":              readyConfigJSON,
				"/dataplanes+insights": listBody(t, ins),
			})
			f, got := findFinding(m, "blocker", "Dataplane version", title)
			if got != tc.want {
				t.Fatalf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
			if got && f.Group != groupUpgradePath {
				t.Errorf("group = %q, want %q", f.Group, groupUpgradePath)
			}
			if got && m.Findings[0].Title != title {
				t.Errorf("first finding = %q, want %q", m.Findings[0].Title, title)
			}
		})
	}
}
