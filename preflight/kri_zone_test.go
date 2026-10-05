package preflight

import (
	"strings"
	"testing"
)

// TestKriZoneFromConnectedZoneCP: a resource created before 2.8 carries no
// kuma.io/zone, but on a directly audited zone CP its KRI must still name the
// zone — 3.0 materializes the zone on read, and its KRI endpoint resolves a
// resource as locally originated only when the KRI zone matches the CP's. A
// resource synced down from the global keeps no zone.
func TestKriZoneFromConnectedZoneCP(t *testing.T) {
	cfg := strings.Replace(readyConfigJSON, `"mode": "zone",`,
		`"mode": "zone", "multizone": {"zone": {"name": "east"}},`, 1)
	policies := listBody(t,
		map[string]any{
			"type": "MeshTimeout", "mesh": "default", "name": "old-timeout",
			"spec": map[string]any{"from": []any{map[string]any{"targetRef": map[string]any{"kind": "Mesh"}}}},
		},
		map[string]any{
			"type": "MeshTimeout", "mesh": "default", "name": "synced-timeout",
			"labels": map[string]any{"kuma.io/origin": "global"},
			"spec":   map[string]any{"from": []any{map[string]any{"targetRef": map[string]any{"kind": "Mesh"}}}},
		},
	)
	var requested []string
	m := auditResponsesFunc(t, func(path string) (string, int, bool) {
		requested = append(requested, path)
		switch path {
		case "/config":
			return cfg, 200, true
		case "/meshes":
			return listBody(t, map[string]any{"type": "Mesh", "name": "default"}), 200, true
		case "/meshtimeouts":
			return policies, 200, true
		}
		return "", 0, false
	})
	f, ok := findFinding(m, "blocker", "Policy `from` field", "MeshTimeout uses `from`")
	if !ok {
		for _, p := range requested {
			t.Logf("requested: %s", p)
		}
		t.Fatalf("from-field finding missing; findings=%+v", m.Findings)
	}
	if len(f.Examples) != 2 {
		t.Fatalf("examples = %v, want the local and the synced policy", f.Examples)
	}
	for _, ex := range f.Examples {
		switch {
		case strings.Contains(ex, "old-timeout"):
			if ex != "kri_mt_default_east__old-timeout_" {
				t.Errorf("local example = %q, want the CP's zone in the KRI", ex)
			}
		case strings.Contains(ex, "synced-timeout"):
			if ex != "kri_mt_default___synced-timeout_" {
				t.Errorf("global-origin example = %q, want an empty KRI zone", ex)
			}
		default:
			t.Errorf("unexpected example %q", ex)
		}
	}
}
