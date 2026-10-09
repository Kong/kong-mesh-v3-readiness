package preflight

import (
	"maps"
	"net/http"
	"strings"
	"testing"
)

// crossZoneTrustResponses audits a mock multizone-global control plane whose
// meshes span the given zones, with the given meshidentities/meshtrusts lists.
// Paths listed in notFound answer 404, so a collection is "not observed".
func crossZoneTrustResponses(t *testing.T, zones []string, extra map[string]string, notFound ...string) Report {
	t.Helper()
	dpItems := make([]map[string]any, 0, len(zones))
	for _, z := range zones {
		dpItems = append(dpItems, universalDP("default", "dp-"+z, z))
	}
	zoneItems := make([]map[string]any, 0, len(zones))
	for _, z := range zones {
		zoneItems = append(zoneItems, map[string]any{"type": "ZoneOverview", "name": z})
	}
	r := map[string]string{
		"/config":         `{"mode": "global", "environment": "universal"}`,
		"/meshes":         listBody(t, map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}}),
		"/zones+insights": listBody(t, zoneItems...),
		"/dataplanes":     listBody(t, dpItems...),
	}
	maps.Copy(r, extra)
	return auditWithNotFound(t, r, notFound...)
}

// bundledIdentity is a MeshIdentity whose provider is the Bundled one, the shape
// whose zone-origin MeshTrusts do not propagate across zones.
func bundledIdentity() map[string]any {
	return map[string]any{
		"type": "MeshIdentity", "mesh": "default", "name": "mi",
		"spec": map[string]any{"provider": map[string]any{"type": "Bundled"}},
	}
}

// zoneTrust is a zone-local MeshTrust as a zone control plane auto-generates it:
// zone-labeled on the global, carrying only that zone's CA bundle.
func zoneTrust(zone string) map[string]any {
	return map[string]any{
		"type": "MeshTrust", "mesh": "default", "name": "trust-" + zone,
		"labels": map[string]any{"kuma.io/zone": zone},
		"spec": map[string]any{
			"trustDomain": "default.mesh.local",
			"caBundles":   []any{map[string]any{"type": "Pem", "pem": map[string]any{"value": "-----BEGIN CERTIFICATE-----\n" + zone + "\n-----END CERTIFICATE-----"}}},
		},
	}
}

// TestCrossZoneTrustFederationMissing covers the firing case: a mesh whose
// Bundled MeshIdentity spans zones but whose every MeshTrust is zone-local has
// no trust federation, so cross-zone mTLS dies after the upgrade. It is an info:
// the mesh may not need cross-zone traffic, and zone-local trusts may already
// carry the peers' CAs — the check cannot verify bundles.
func TestCrossZoneTrustFederationMissing(t *testing.T) {
	m := crossZoneTrustResponses(t, []string{"east", "west"}, map[string]string{
		"/meshidentities": listBody(t, bundledIdentity()),
		"/meshtrusts":     listBody(t, zoneTrust("east"), zoneTrust("west")),
	})
	f, ok := findFinding(m, "info", "MeshIdentity coverage", "Zone-spanning mesh has no federated MeshTrust")
	if !ok {
		t.Fatalf("zone-spanning mesh with only zone-local MeshTrusts not flagged\nfindings: %+v", m.Findings)
	}
	if !strings.Contains(f.Examples[0], "mesh default") || !strings.Contains(f.Examples[0], "east") || !strings.Contains(f.Examples[0], "west") {
		t.Errorf("example = %q, want it to name the mesh and its zones", f.Examples[0])
	}
	if !strings.Contains(f.Detail, "federated MeshTrust on the global") {
		t.Errorf("detail = %q, want the federated-trust remediation", f.Detail)
	}
}

// TestCrossZoneTrustFederatedTrustSatisfies guards the silent path: a
// global-origin MeshTrust (no zone label, or the kuma.io/origin: global a
// zone-synced copy keeps) propagates to every zone, so the federation exists.
func TestCrossZoneTrustFederatedTrustSatisfies(t *testing.T) {
	globalTrust := func(mut func(map[string]any)) map[string]any {
		it := map[string]any{
			"type": "MeshTrust", "mesh": "default", "name": "federated",
			"spec": map[string]any{
				"trustDomain": "default.mesh.local",
				"caBundles":   []any{map[string]any{"type": "Pem", "pem": map[string]any{"value": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"}}},
			},
		}
		if mut != nil {
			mut(it)
		}
		return it
	}
	for name, mut := range map[string]func(map[string]any){
		"created on the global": nil,
		"zone-synced global origin": func(it map[string]any) {
			it["labels"] = map[string]any{"kuma.io/zone": "east", "kuma.io/origin": "global"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := crossZoneTrustResponses(t, []string{"east", "west"}, map[string]string{
				"/meshidentities": listBody(t, bundledIdentity()),
				"/meshtrusts":     listBody(t, zoneTrust("east"), zoneTrust("west"), globalTrust(mut)),
			})
			if _, ok := findFinding(m, "info", "MeshIdentity coverage", "Zone-spanning mesh has no federated MeshTrust"); ok {
				t.Errorf("mesh with a global-origin MeshTrust flagged\nfindings: %+v", m.Findings)
			}
		})
	}
}

// TestCrossZoneTrustOneZoneMeshInMultizoneEstate pins the per-mesh zone-count
// precondition: a mesh whose proxies all sit in one zone of a two-zone estate
// spans nothing, so the estate-level guard alone must not let the check fire.
func TestCrossZoneTrustOneZoneMeshInMultizoneEstate(t *testing.T) {
	m := crossZoneTrustResponses(t, []string{"east", "west"}, map[string]string{
		"/dataplanes":     listBody(t, universalDP("default", "dp-e", "east")),
		"/meshidentities": listBody(t, bundledIdentity()),
		"/meshtrusts":     listBody(t, zoneTrust("east")),
	})
	if _, ok := findFinding(m, "info", "MeshIdentity coverage", "Zone-spanning mesh has no federated MeshTrust"); ok {
		t.Errorf("single-zone mesh in a multizone estate flagged\nfindings: %+v", m.Findings)
	}
}

// TestCrossZoneTrustTrustCreationDisabled branches the causal story: with
// `meshTrustCreation: Disabled` no zone control plane generates a MeshTrust at
// all, so the detail must not claim every zone trusts "its own CA".
func TestCrossZoneTrustTrustCreationDisabled(t *testing.T) {
	id := bundledIdentity()
	id["spec"] = map[string]any{"provider": map[string]any{
		"type": "Bundled", "bundled": map[string]any{"meshTrustCreation": "Disabled"},
	}}
	m := crossZoneTrustResponses(t, []string{"east", "west"}, map[string]string{
		"/meshidentities": listBody(t, id),
		"/meshtrusts":     listBody(t),
	})
	f, ok := findFinding(m, "info", "MeshIdentity coverage", "Zone-spanning mesh has no federated MeshTrust")
	if !ok {
		t.Fatalf("mesh with meshTrustCreation Disabled not flagged\nfindings: %+v", m.Findings)
	}
	if !strings.Contains(f.Detail, "meshTrustCreation: Disabled") {
		t.Errorf("detail = %q, want the disabled-creation cause", f.Detail)
	}
}

// TestCrossZoneTrustPreconditions covers the states the check must stay silent
// in: no Bundled provider, a zone-local mesh, a CP that is not a multi-zone
// global, and a MeshIdentity list the CP does not register (a 404 on a newer
// type is "not applicable", not absence).
func TestCrossZoneTrustPreconditions(t *testing.T) {
	cases := []struct {
		name       string
		zones      []string
		identities string
		notFound   []string
	}{
		{
			name: "spire provider manages trust differently", zones: []string{"east", "west"},
			identities: listBody(t, map[string]any{
				"type": "MeshIdentity", "mesh": "default", "name": "mi",
				"spec": map[string]any{"provider": map[string]any{"type": "Spire"}},
			}),
		},
		{
			name: "mesh local to one zone", zones: []string{"east"},
			identities: listBody(t, bundledIdentity()),
		},
		{
			name: "no MeshIdentity served at all", zones: []string{"east", "west"},
			notFound: []string{"/meshidentities"},
		},
		{
			name: "a global with a single zone has no cross-zone traffic", zones: []string{"east"},
			identities: listBody(t, bundledIdentity()),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]string{}
			if tc.identities != "" {
				extra["/meshidentities"] = tc.identities
			}
			m := crossZoneTrustResponses(t, tc.zones, extra, tc.notFound...)
			if _, ok := findFinding(m, "info", "MeshIdentity coverage", "Zone-spanning mesh has no federated MeshTrust"); ok {
				t.Errorf("flagged\nfindings: %+v", m.Findings)
			}
		})
	}
}

// TestCrossZoneTrustUnregisteredTrustTypeIsGap guards the "not observed is not
// absent" rule for the trust list: a CP that serves MeshIdentity but has not
// registered MeshTrust can neither confirm nor deny federation, so the run must
// be inconclusive rather than flag every mesh or silently pass.
func TestCrossZoneTrustUnregisteredTrustTypeIsGap(t *testing.T) {
	m := crossZoneTrustResponses(t, []string{"east", "west"}, map[string]string{
		"/meshidentities": listBody(t, bundledIdentity()),
	}, "/meshtrusts")
	if _, ok := findFinding(m, "info", "MeshIdentity coverage", "Zone-spanning mesh has no federated MeshTrust"); ok {
		t.Errorf("unregistered MeshTrust type flagged\nfindings: %+v", m.Findings)
	}
	if m.Status != "inconclusive" {
		t.Errorf("status = %q, want inconclusive — the trust list was not observed", m.Status)
	}
}

// TestCrossZoneTrustGapNotDuplicated guards the coverage-gap dedupe: this check
// and checkMeshTrust both read /meshtrusts, and a failing read must yield one
// coverage gap, not two.
func TestCrossZoneTrustGapNotDuplicated(t *testing.T) {
	global := map[string]string{
		"/config":         `{"mode": "global", "environment": "universal"}`,
		"/meshes":         listBody(t, map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}}),
		"/zones+insights": listBody(t, map[string]any{"type": "ZoneOverview", "name": "east"}, map[string]any{"type": "ZoneOverview", "name": "west"}),
		"/dataplanes":     listBody(t, universalDP("default", "dp-e", "east"), universalDP("default", "dp-w", "west")),
		"/meshidentities": listBody(t, bundledIdentity()),
	}
	m := auditResponsesFunc(t, func(path string) (string, int, bool) {
		if path == "/meshtrusts" {
			return "", http.StatusInternalServerError, true
		}
		if body, ok := global[path]; ok {
			return body, http.StatusOK, true
		}
		return "", http.StatusOK, false
	})
	n := 0
	for _, g := range m.Coverage {
		if g.Path == "/meshtrusts" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("coverage gaps for /meshtrusts = %d, want 1\ngaps: %+v", n, m.Coverage)
	}
}

// TestMeshMTLSMigrationWarnsAboutCrossZoneTrust pins the sentence the inline-mTLS
// blocker carries for multizone meshes: migrating to a Bundled MeshIdentity is
// not enough, the federated MeshTrusts must exist too.
func TestMeshMTLSMigrationWarnsAboutCrossZoneTrust(t *testing.T) {
	m := auditMesh(t, map[string]any{"mtls": map[string]any{"enabledBackend": "ca-1"}})
	f, ok := findFinding(m, "blocker", "Mesh object settings", "Inline mTLS on Mesh")
	if !ok {
		t.Fatalf("inline mTLS not flagged\nfindings: %+v", m.Findings)
	}
	if !strings.Contains(f.Detail, "zone-origin MeshTrusts do not propagate") {
		t.Errorf("detail = %q, want the cross-zone federation warning", f.Detail)
	}
}
