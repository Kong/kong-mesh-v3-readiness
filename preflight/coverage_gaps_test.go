package preflight

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// TestUniversalDataplaneNetworkingFields covers the Universal Dataplane fields
// 3.0 rejects, drops or silently ignores: each must surface as its own blocker,
// and none may fire for a Kubernetes proxy, whose Dataplane the control plane
// generates (and a 3.0 control plane regenerates).
func TestUniversalDataplaneNetworkingFields(t *testing.T) {
	cases := []struct {
		name  string
		net   map[string]any
		title string
	}{
		{
			name:  "advertisedAddress",
			net:   map[string]any{"advertisedAddress": "10.0.0.9"},
			title: "Dataplane uses networking.advertisedAddress",
		},
		{
			name: "inbound tags",
			net: map[string]any{"inbound": []any{
				map[string]any{"port": 8080, "tags": map[string]any{"kuma.io/service": "backend"}},
			}},
			title: "Dataplane uses networking.inbound[].tags",
		},
		{
			name: "outbound without backendRef",
			net: map[string]any{"outbound": []any{
				map[string]any{"port": 10001, "tags": map[string]any{"kuma.io/service": "frontend"}},
			}},
			title: "Dataplane outbound has no backendRef",
		},
		{
			name: "named directAccessServices",
			net: map[string]any{"transparentProxying": map[string]any{
				"directAccessServices": []any{"frontend"},
			}},
			title: "Dataplane names individual directAccessServices",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditDataplane(t, map[string]any{
				"labels":     map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "backend"},
				"networking": tc.net,
			})
			if _, ok := findFinding(m, "blocker", "Dataplane networking", tc.title); !ok {
				t.Fatalf("missing blocker %q\nfindings: %+v", tc.title, m.Findings)
			}
		})
	}
}

// TestDataplaneNetworkingChecksSkipKubernetes confirms the hand-written-Universal
// checks stay off Kubernetes proxies. directAccessServices is deliberately absent
// here: it is honored on both environments, so it is checked regardless of env.
func TestDataplaneNetworkingChecksSkipKubernetes(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"labels": map[string]any{"kuma.io/env": "kubernetes"},
		"networking": map[string]any{
			"advertisedAddress": "10.0.0.9",
			"inbound":           []any{map[string]any{"port": 8080, "tags": map[string]any{"kuma.io/service": "backend"}}},
			"outbound":          []any{map[string]any{"port": 10001, "tags": map[string]any{"kuma.io/service": "frontend"}}},
			// Every k8s sidecar is transparent; this keeps the reachableBackends
			// default check (covered elsewhere) out of this test.
			"transparentProxying": map[string]any{"reachableBackends": map[string]any{}},
		},
	})
	for _, f := range m.Findings {
		if f.Category == "Dataplane networking" {
			t.Errorf("k8s dataplane wrongly flagged: %q", f.Title)
		}
	}
	if m.Status != StatusClean {
		t.Errorf("status = %q, want %q", m.Status, StatusClean)
	}
}

// TestDirectAccessServicesWildcardIsClean guards the one value 3.0 still honors.
// A list that also carries `*` already grants access to everything, so dropping
// per-service matching changes nothing for it either.
func TestDirectAccessServicesWildcardIsClean(t *testing.T) {
	for _, services := range [][]any{{"*"}, {"*", "frontend"}, {}} {
		m := auditDataplane(t, map[string]any{
			"labels": map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "backend"},
			"networking": map[string]any{
				"transparentProxying": map[string]any{"directAccessServices": services},
			},
		})
		if _, ok := findFinding(m, "blocker", "Dataplane networking", "Dataplane names individual directAccessServices"); ok {
			t.Errorf("directAccessServices %v wrongly flagged\nfindings: %+v", services, m.Findings)
		}
	}
}

// TestOutboundWithBackendRefIsClean guards the migrated outbound shape.
func TestOutboundWithBackendRefIsClean(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"labels": map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "backend"},
		"networking": map[string]any{"outbound": []any{
			map[string]any{"port": 10001, "backendRef": map[string]any{"kind": "MeshService", "name": "frontend", "port": 80}},
		}},
	})
	if _, ok := findFinding(m, "blocker", "Dataplane networking", "Dataplane outbound has no backendRef"); ok {
		t.Errorf("outbound with a backendRef wrongly flagged\nfindings: %+v", m.Findings)
	}
}

// TestGatewayLabelValue checks the delegated-gateway marker: 3.0 reads
// kuma.io/gateway as a boolean, so the 2.x annotation value carried over as a
// label is a blocker while "true"/"false" are not. An empty label value is not a
// boolean either, so it is flagged too.
func TestGatewayLabelValue(t *testing.T) {
	const title = "Dataplane kuma.io/gateway label is not a boolean"
	for _, tc := range []struct {
		value    string
		wantFlag bool
	}{
		{"enabled", true},
		{"", true},
		{"true", false},
		{"false", false},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			m := auditDataplane(t, map[string]any{"labels": map[string]any{
				"kuma.io/env": "universal", "kuma.io/workload": "backend", "kuma.io/gateway": tc.value,
			}})
			_, got := findFinding(m, "blocker", "Gateway in Dataplane", title)
			if got != tc.wantFlag {
				t.Errorf("kuma.io/gateway=%q flagged = %v, want %v\nfindings: %+v", tc.value, got, tc.wantFlag, m.Findings)
			}
		})
	}
}

// TestGatewayLabelCheckSkipsKubernetes guards against advice that would be wrong
// on Kubernetes: 2.14 merges Pod labels onto the Dataplane, so a stray
// kuma.io/gateway lands there, and the 3.0 pod controller recomputes the label
// from the Pod annotation (deleting it for a non-gateway). Telling an operator to
// set it to "true" would convert a sidecar into a gateway.
func TestGatewayLabelCheckSkipsKubernetes(t *testing.T) {
	m := auditDataplane(t, map[string]any{"labels": map[string]any{
		"kuma.io/env": "kubernetes", "kuma.io/gateway": "enabled",
	}})
	if _, ok := findFinding(m, "blocker", "Gateway in Dataplane", "Dataplane kuma.io/gateway label is not a boolean"); ok {
		t.Errorf("k8s dataplane wrongly flagged for a stray gateway label\nfindings: %+v", m.Findings)
	}
	if m.Status != StatusClean {
		t.Errorf("status = %q, want %q", m.Status, StatusClean)
	}
}

// TestUniversalGatewaySpecMigration covers the marker a real 2.14 Universal
// gateway actually carries: networking.gateway in the spec. 2.14 never computes
// the kuma.io/gateway label, so without this the whole delegated-gateway
// migration is invisible to the audit.
func TestUniversalGatewaySpecMigration(t *testing.T) {
	dp := func(gateway map[string]any, labels map[string]any) map[string]any {
		l := map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "gw"}
		maps.Copy(l, labels)
		return map[string]any{"labels": l, "networking": map[string]any{"gateway": gateway}}
	}
	delegated := map[string]any{"type": "DELEGATED", "tags": map[string]any{"kuma.io/service": "gw"}}

	t.Run("delegated gateway without the label is flagged", func(t *testing.T) {
		m := auditDataplane(t, dp(delegated, nil))
		if _, ok := findFinding(m, "blocker", "Gateway in Dataplane", "Dataplane marks a gateway with networking.gateway"); !ok {
			t.Fatalf("universal delegated gateway not flagged\nfindings: %+v", m.Findings)
		}
	})
	t.Run("gateway with no explicit type defaults to delegated", func(t *testing.T) {
		m := auditDataplane(t, dp(map[string]any{"tags": map[string]any{"kuma.io/service": "gw"}}, nil))
		if _, ok := findFinding(m, "blocker", "Gateway in Dataplane", "Dataplane marks a gateway with networking.gateway"); !ok {
			t.Fatalf("gateway with no type not flagged\nfindings: %+v", m.Findings)
		}
	})
	t.Run("already migrated gateway is not flagged", func(t *testing.T) {
		m := auditDataplane(t, dp(delegated, map[string]any{"kuma.io/gateway": "true"}))
		if _, ok := findFinding(m, "blocker", "Gateway in Dataplane", "Dataplane marks a gateway with networking.gateway"); ok {
			t.Errorf("gateway already carrying the label wrongly flagged\nfindings: %+v", m.Findings)
		}
	})
	t.Run("builtin gateway is flagged as removed", func(t *testing.T) {
		m := auditDataplane(t, dp(map[string]any{"type": "BUILTIN", "tags": map[string]any{"kuma.io/service": "gw"}}, nil))
		if _, ok := findFinding(m, "blocker", "Gateway in Dataplane", "Dataplane is a builtin gateway"); !ok {
			t.Fatalf("builtin gateway not flagged\nfindings: %+v", m.Findings)
		}
	})
	t.Run("kubernetes gateway is not flagged", func(t *testing.T) {
		m := auditDataplane(t, map[string]any{
			"labels":     map[string]any{"kuma.io/env": "kubernetes"},
			"networking": map[string]any{"gateway": delegated},
		})
		for _, f := range m.Findings {
			if f.Category == "Gateway in Dataplane" {
				t.Errorf("k8s gateway wrongly flagged: %q", f.Title)
			}
		}
	})
}

// TestServiceAccountLabelIsUniversalOnly checks the identity label: on Universal
// it can only be a copied leftover, on Kubernetes it is on every control-plane
// created Dataplane and a manual check covers the GitOps case instead.
func TestServiceAccountLabelIsUniversalOnly(t *testing.T) {
	const title = "Universal Dataplane carries the k8s.kuma.io/service-account label"
	t.Run("universal is flagged", func(t *testing.T) {
		m := auditDataplane(t, map[string]any{"labels": map[string]any{
			"kuma.io/env": "universal", "kuma.io/workload": "backend", "k8s.kuma.io/service-account": "backend",
		}})
		if _, ok := findFinding(m, "blocker", "Dataplane identity", title); !ok {
			t.Errorf("universal dataplane with the label not flagged\nfindings: %+v", m.Findings)
		}
	})
	t.Run("kubernetes is not flagged", func(t *testing.T) {
		m := auditDataplane(t, map[string]any{"labels": map[string]any{
			"kuma.io/env": "kubernetes", "k8s.kuma.io/service-account": "backend",
		}})
		if _, ok := findFinding(m, "blocker", "Dataplane identity", title); ok {
			t.Errorf("k8s dataplane wrongly flagged\nfindings: %+v", m.Findings)
		}
	})
}

// TestZoneNameFromZonesCollection checks the zone-name rule against a global's
// /zones: a dotted name is a blocker, a DNS label is not.
func TestZoneNameFromZonesCollection(t *testing.T) {
	const title = "Zone name is not a valid RFC-1035 DNS label"
	m := auditResponses(t, map[string]string{"/zones": listBody(t,
		map[string]any{"type": "Zone", "name": "eu.west"},
		map[string]any{"type": "Zone", "name": "east"},
	)})
	f, ok := findFinding(m, "blocker", "Non-RFC-1035 names", title)
	if !ok {
		t.Fatalf("dotted zone name not flagged\nfindings: %+v", m.Findings)
	}
	if f.Count != 1 {
		t.Errorf("count = %d, want 1 (only eu.west is invalid)", f.Count)
	}
	if len(f.Examples) != 1 || f.Examples[0] != "eu.west" {
		t.Errorf("examples = %v, want [eu.west]", f.Examples)
	}
}

// TestZoneNameFromZoneControlPlaneConfig covers the fallback source: Zone
// resources live on the global and are not synced down, so a directly audited
// zone CP is checked against its own multizone.zone.name.
func TestZoneNameFromZoneControlPlaneConfig(t *testing.T) {
	const title = "Zone name is not a valid RFC-1035 DNS label"
	cfg := strings.Replace(readyConfigJSON, `"mode": "zone",`, `"mode": "zone", "multizone": {"zone": {"name": "eu.west"}},`, 1)
	m := auditResponses(t, map[string]string{"/config": cfg})
	f, ok := findFinding(m, "blocker", "Non-RFC-1035 names", title)
	if !ok {
		t.Fatalf("zone CP with a dotted configured name not flagged\nfindings: %+v", m.Findings)
	}
	if len(f.Examples) != 1 || !strings.Contains(f.Examples[0], "eu.west") {
		t.Errorf("examples = %v, want one naming eu.west", f.Examples)
	}
}

// TestZoneNameNotDoubleCountedOnGlobal guards against the two zone-name sources
// overlapping: a global reads /zones, and its fanned-out zone configs must not
// re-flag the same zone.
func TestZoneNameNotDoubleCountedOnGlobal(t *testing.T) {
	zoneCfg := `{"mode": "zone", "environment": "universal", "multizone": {"zone": {"name": "eu.west"}}, ` +
		`"experimental": {"deltaXds": true, "sidecarContainers": true, "inboundTagsDisabled": true, ` +
		`"kdsEventBasedWatchdog": {"enabled": true}}}`
	m := auditResponses(t, map[string]string{
		"/config": `{"mode": "global", "environment": "universal"}`,
		"/zones":  listBody(t, map[string]any{"type": "Zone", "name": "eu.west"}),
		"/zones+insights": listBody(t, map[string]any{
			"type": "ZoneOverview", "name": "eu.west",
			"zoneInsight": map[string]any{"subscriptions": []any{map[string]any{"config": zoneCfg}}},
		}),
	})
	f, ok := findFinding(m, "blocker", "Non-RFC-1035 names", "Zone name is not a valid RFC-1035 DNS label")
	if !ok {
		t.Fatalf("zone name not flagged on a global\nfindings: %+v", m.Findings)
	}
	if f.Count != 1 {
		t.Errorf("count = %d, want 1 — /zones and the zone config fan-out double-counted the zone", f.Count)
	}
}

// TestMeshZoneAddressPerMeshAndZone covers the cross-zone readiness rule.
// MeshZoneAddress is mesh-scoped, so coverage in one mesh must not satisfy
// another; and the rule applies only to a zone-spanning mesh whose zone
// terminates cross-zone traffic on Universal.
func TestMeshZoneAddressPerMeshAndZone(t *testing.T) {
	const title = "Mesh has no MeshZoneAddress for a zone it spans"
	// Two meshes, both spanning east+west, with a Universal zone proxy in east.
	globalResponses := func(extra map[string]string) map[string]string {
		r := map[string]string{
			"/config": `{"mode": "global", "environment": "universal"}`,
			"/meshes": listBody(t,
				map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}},
				map[string]any{"type": "Mesh", "name": "payments", "meshServices": map[string]any{"mode": "Exclusive"}},
			),
			"/zones+insights": listBody(t,
				map[string]any{"type": "ZoneOverview", "name": "east"},
				map[string]any{"type": "ZoneOverview", "name": "west"},
			),
			"/zoneingresses": listBody(t, map[string]any{
				"type": "ZoneIngress", "name": "zi-east", "zone": "east",
				"labels": map[string]any{"kuma.io/env": "universal"},
			}),
			"/dataplanes": listBody(t,
				universalDP("default", "dp-e", "east"), universalDP("default", "dp-w", "west"),
				universalDP("payments", "pay-e", "east"), universalDP("payments", "pay-w", "west"),
			),
		}
		maps.Copy(r, extra)
		return r
	}
	examples := func(m Report) []string {
		f, ok := findFinding(m, "blocker", "Zone proxies", title)
		if !ok {
			return nil
		}
		return f.Examples
	}

	t.Run("every zone-spanning mesh is required to cover the zone", func(t *testing.T) {
		got := examples(auditResponses(t, globalResponses(nil)))
		want := []string{"mesh default, zone east", "mesh payments, zone east"}
		if !slices.Equal(got, want) {
			t.Errorf("examples = %v, want %v", got, want)
		}
	})

	t.Run("coverage in one mesh does not satisfy another", func(t *testing.T) {
		got := examples(auditResponses(t, globalResponses(map[string]string{
			"/meshzoneaddresses": listBody(t, map[string]any{
				"type": "MeshZoneAddress", "mesh": "default", "name": "east-ingress",
				"labels": map[string]any{"kuma.io/zone": "east"},
			}),
		})))
		want := []string{"mesh payments, zone east"}
		if !slices.Equal(got, want) {
			t.Errorf("examples = %v, want %v — a MeshZoneAddress in one mesh covered another", got, want)
		}
	})

	t.Run("fully covered estate is not flagged", func(t *testing.T) {
		got := examples(auditResponses(t, globalResponses(map[string]string{
			"/meshzoneaddresses": listBody(t,
				map[string]any{
					"type": "MeshZoneAddress", "mesh": "default", "name": "east-ingress",
					"labels": map[string]any{"kuma.io/zone": "east"},
				},
				map[string]any{
					"type": "MeshZoneAddress", "mesh": "payments", "name": "east-ingress",
					"labels": map[string]any{"kuma.io/zone": "east"},
				},
			),
		})))
		if got != nil {
			t.Errorf("covered estate flagged: %v", got)
		}
	})

	t.Run("zone-local mesh is not required to cover the zone", func(t *testing.T) {
		got := examples(auditResponses(t, globalResponses(map[string]string{
			"/dataplanes": listBody(t,
				universalDP("default", "dp-e", "east"), universalDP("default", "dp-w", "west"),
				universalDP("payments", "pay-e", "east"),
			),
			"/meshzoneaddresses": listBody(t, map[string]any{
				"type": "MeshZoneAddress", "mesh": "default", "name": "east-ingress",
				"labels": map[string]any{"kuma.io/zone": "east"},
			}),
		})))
		if got != nil {
			t.Errorf("mesh confined to one zone wrongly flagged: %v", got)
		}
	})

	t.Run("kubernetes zone proxy is not flagged", func(t *testing.T) {
		got := examples(auditResponses(t, globalResponses(map[string]string{
			"/zoneingresses": listBody(t, map[string]any{
				"type": "ZoneIngress", "name": "zi-east", "zone": "east",
				"labels": map[string]any{"kuma.io/env": "kubernetes"},
			}),
		})))
		if got != nil {
			t.Errorf("kubernetes zone flagged, but the 3.0 CP creates the resource itself: %v", got)
		}
	})

	t.Run("single-zone estate is not checked", func(t *testing.T) {
		got := examples(auditResponses(t, globalResponses(map[string]string{
			"/zones+insights": listBody(t, map[string]any{"type": "ZoneOverview", "name": "east"}),
		})))
		if got != nil {
			t.Errorf("single-zone estate wrongly flagged: %v", got)
		}
	})
}

// universalDP is a migrated Universal Dataplane in a mesh and zone, carrying no
// deprecated construct of its own so it contributes only its mesh/zone presence.
func universalDP(mesh, name, zone string) map[string]any {
	return map[string]any{
		"type": "Dataplane", "mesh": mesh, "name": name,
		"labels": map[string]any{
			"kuma.io/env": "universal", "kuma.io/zone": zone, "kuma.io/workload": name,
		},
		"networking": map[string]any{"inbound": []any{map[string]any{"port": 8080}}},
	}
}

// TestMeshZoneAddressUnservedIsCoverageGap guards the "not observed is not
// absent" rule: a control plane that does not serve MeshZoneAddress cannot prove
// cross-zone readiness either way, so the run must be inconclusive rather than
// flag every zone or silently pass.
func TestMeshZoneAddressUnservedIsCoverageGap(t *testing.T) {
	m := auditWithNotFound(t, map[string]string{
		"/config": `{"mode": "global", "environment": "universal"}`,
		"/zones+insights": listBody(t,
			map[string]any{"type": "ZoneOverview", "name": "east"},
			map[string]any{"type": "ZoneOverview", "name": "west"},
		),
		"/zoneingresses": listBody(t, map[string]any{
			"type": "ZoneIngress", "name": "zi-east", "zone": "east",
			"labels": map[string]any{"kuma.io/env": "universal"},
		}),
		"/dataplanes": listBody(t, universalDP("default", "dp-e", "east"), universalDP("default", "dp-w", "west")),
	}, "/meshzoneaddresses")

	if _, ok := findFinding(m, "blocker", "Zone proxies", "Mesh has no MeshZoneAddress for a zone it spans"); ok {
		t.Errorf("an unserved collection must not produce a per-zone blocker\nfindings: %+v", m.Findings)
	}
	gapped := false
	for _, g := range m.Coverage {
		if g.Path == "/meshzoneaddresses" {
			gapped = true
		}
	}
	if !gapped {
		t.Errorf("no coverage gap recorded for /meshzoneaddresses: %+v", m.Coverage)
	}
	if m.Status != StatusInconclusive {
		t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
	}
}

// TestMeshHTTPRouteCatchAll checks the 3.0 404-on-no-match rule: a route with no
// catch-all rule is surfaced for review, one with a catch-all is not.
func TestMeshHTTPRouteCatchAll(t *testing.T) {
	const title = "MeshHTTPRoute has no catch-all rule"
	route := func(rules ...map[string]any) string {
		return listBody(t, map[string]any{
			"type": "MeshHTTPRoute", "mesh": "default", "name": "r-1",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{map[string]any{
					"targetRef": map[string]any{"kind": "MeshService", "labels": map[string]any{"kuma.io/display-name": "backend"}},
					"rules":     rules,
				}},
			},
		})
	}
	prefix := func(v string) map[string]any {
		return map[string]any{"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": v}}}}
	}

	for _, tc := range []struct {
		name  string
		rules []map[string]any
		want  bool
	}{
		{"anchor-only route", []map[string]any{prefix("/api")}, true},
		{"route with a catch-all rule", []map[string]any{prefix("/api"), prefix("/")}, false},
		{
			name: "root prefix narrowed by a method matcher is not a catch-all",
			rules: []map[string]any{{"matches": []any{map[string]any{
				"path": map[string]any{"type": "PathPrefix", "value": "/"}, "method": "GET",
			}}}},
			want: true,
		},
		{
			name:  "exact match on / is not a catch-all",
			rules: []map[string]any{{"matches": []any{map[string]any{"path": map[string]any{"type": "Exact", "value": "/"}}}}},
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/meshhttproutes": route(tc.rules...)})
			_, got := findFinding(m, "info", "MeshHTTPRoute routing", title)
			if got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
			if tc.want && m.Status != StatusClean {
				t.Errorf("status = %q, want %q — an info finding must not gate the run", m.Status, StatusClean)
			}
		})
	}
}

// TestMeshLoadBalancingStrategyCrossZone checks the 3.0 constraint that
// localityAwareness.crossZone is only valid against a MeshMultiZoneService.
func TestMeshLoadBalancingStrategyCrossZone(t *testing.T) {
	const title = "MeshLoadBalancingStrategy crossZone targets a non-MeshMultiZoneService"
	policy := func(kind string) string {
		return listBody(t, map[string]any{
			"type": "MeshLoadBalancingStrategy", "mesh": "default", "name": "mlbs-1",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{map[string]any{
					"targetRef": map[string]any{"kind": kind, "name": "backend"},
					"default": map[string]any{"localityAwareness": map[string]any{
						"crossZone": map[string]any{"failoverThreshold": map[string]any{"percentage": 50}},
					}},
				}},
			},
		})
	}
	t.Run("MeshService target is flagged", func(t *testing.T) {
		m := auditResponses(t, map[string]string{"/meshloadbalancingstrategies": policy("MeshService")})
		if _, ok := findFinding(m, "blocker", "Cross-zone load balancing", title); !ok {
			t.Fatalf("crossZone on a MeshService target not flagged\nfindings: %+v", m.Findings)
		}
	})
	t.Run("MeshMultiZoneService target is not flagged", func(t *testing.T) {
		m := auditResponses(t, map[string]string{"/meshloadbalancingstrategies": policy("MeshMultiZoneService")})
		if _, ok := findFinding(m, "blocker", "Cross-zone load balancing", title); ok {
			t.Errorf("crossZone on a MeshMultiZoneService wrongly flagged\nfindings: %+v", m.Findings)
		}
	})
}

// TestNewManualChecksAreListed guards that the non-detectable items reach the
// checklist, and that the Kubernetes-only ones stay off a Universal-only run.
// auditResponses serves a Kubernetes /config by default.
func TestNewManualChecksAreListed(t *testing.T) {
	k8s := auditResponses(t, nil)
	universal := auditResponses(t, map[string]string{
		"/config": strings.Replace(readyConfigJSON, `"environment": "kubernetes"`, `"environment": "universal"`, 1),
	})
	has := func(m Report, title string) bool {
		for _, c := range m.Manual {
			if c.Title == title {
				return true
			}
		}
		return false
	}
	const (
		loopback = "Re-check kumactl access on a Helm-installed Universal control plane"
		tags     = "Drop the `kuma.io/tags` Pod annotation"
		sa       = "Remove `k8s.kuma.io/service-account` from hand-applied Dataplanes"
	)
	for _, title := range []string{loopback, tags, sa} {
		if !has(k8s, title) {
			t.Errorf("manual check %q missing from a Kubernetes run", title)
		}
	}
	if !has(universal, loopback) {
		t.Errorf("manual check %q missing from a Universal run", loopback)
	}
	for _, title := range []string{tags, sa} {
		if has(universal, title) {
			t.Errorf("Kubernetes-only manual check %q shown on a Universal run", title)
		}
	}
}
