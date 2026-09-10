package preflight

import (
	"maps"
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
func TestDirectAccessServicesWildcardIsClean(t *testing.T) {
	m := auditDataplane(t, map[string]any{
		"labels": map[string]any{"kuma.io/env": "universal", "kuma.io/workload": "backend"},
		"networking": map[string]any{
			"transparentProxying": map[string]any{"directAccessServices": []any{"*"}},
		},
	})
	if _, ok := findFinding(m, "blocker", "Dataplane networking", "Dataplane names individual directAccessServices"); ok {
		t.Errorf("`*` directAccessServices wrongly flagged\nfindings: %+v", m.Findings)
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

// TestMeshZoneAddressPerZone covers the cross-zone readiness rule: a zone that
// terminates cross-zone traffic on a multi-zone global needs a MeshZoneAddress.
func TestMeshZoneAddressPerZone(t *testing.T) {
	const title = "Zone has no MeshZoneAddress"
	globalResponses := func(extra map[string]string) map[string]string {
		r := map[string]string{
			"/config": `{"mode": "global", "environment": "universal"}`,
			"/zones+insights": listBody(t,
				map[string]any{"type": "ZoneOverview", "name": "east"},
				map[string]any{"type": "ZoneOverview", "name": "west"},
			),
			"/zoneingresses": listBody(t, map[string]any{"type": "ZoneIngress", "name": "zi-east", "zone": "east"}),
		}
		maps.Copy(r, extra)
		return r
	}

	t.Run("zone proxy without a MeshZoneAddress is flagged", func(t *testing.T) {
		m := auditResponses(t, globalResponses(nil))
		f, ok := findFinding(m, "blocker", "Zone proxies", title)
		if !ok {
			t.Fatalf("missing blocker %q\nfindings: %+v", title, m.Findings)
		}
		if len(f.Examples) != 1 || f.Examples[0] != "zone east" {
			t.Errorf("examples = %v, want [zone east]", f.Examples)
		}
	})

	t.Run("covered zone is not flagged", func(t *testing.T) {
		m := auditResponses(t, globalResponses(map[string]string{
			"/meshzoneaddresses": listBody(t, map[string]any{
				"type": "MeshZoneAddress", "mesh": "default", "name": "east-ingress",
				"labels": map[string]any{"kuma.io/zone": "east"},
			}),
		}))
		if _, ok := findFinding(m, "blocker", "Zone proxies", title); ok {
			t.Errorf("zone with a MeshZoneAddress wrongly flagged\nfindings: %+v", m.Findings)
		}
	})

	t.Run("single-zone estate is not checked", func(t *testing.T) {
		m := auditResponses(t, map[string]string{
			"/config":         `{"mode": "global", "environment": "universal"}`,
			"/zones+insights": listBody(t, map[string]any{"type": "ZoneOverview", "name": "east"}),
			"/zoneingresses":  listBody(t, map[string]any{"type": "ZoneIngress", "name": "zi-east", "zone": "east"}),
		})
		if _, ok := findFinding(m, "blocker", "Zone proxies", title); ok {
			t.Errorf("single-zone estate wrongly flagged\nfindings: %+v", m.Findings)
		}
	})
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
		"/zoneingresses": listBody(t, map[string]any{"type": "ZoneIngress", "name": "zi-east", "zone": "east"}),
	}, "/meshzoneaddresses")

	if _, ok := findFinding(m, "blocker", "Zone proxies", "Zone has no MeshZoneAddress"); ok {
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
					"targetRef": map[string]any{"kind": "MeshService", "name": "backend"},
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
