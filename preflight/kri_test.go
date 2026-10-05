package preflight

import (
	"encoding/json"
	"testing"
)

func TestKriOf(t *testing.T) {
	tests := []struct {
		name string
		item resourceItem
		want string
	}{
		{
			name: "mesh-scoped policy",
			item: resourceItem{Type: "MeshTimeout", Mesh: "default", Name: "my-timeout"},
			want: "kri_mt_default___my-timeout_",
		},
		{
			name: "zone-synced resource carries kuma.io/zone",
			item: resourceItem{
				Type: "MeshService", Mesh: "default", Name: "backend-x4f9",
				Labels: map[string]string{"kuma.io/zone": "east", "kuma.io/display-name": "backend"},
			},
			want: "kri_msvc_default_east__backend_",
		},
		{
			name: "kubernetes resource carries k8s.kuma.io/namespace",
			item: resourceItem{
				Type: "Dataplane", Mesh: "default", Name: "backend-app",
				Labels: map[string]string{"kuma.io/zone": "east", "k8s.kuma.io/namespace": "kuma-demo"},
			},
			want: "kri_dp_default_east_kuma-demo_backend-app_",
		},
		{
			name: "overview resolves to its base resource",
			item: resourceItem{
				Type: "DataplaneOverview", Mesh: "default", Name: "backend-app-x1",
				Labels: map[string]string{"kuma.io/display-name": "backend-app"},
			},
			want: "kri_dp_default___backend-app_",
		},
		{
			name: "zone resource has no mesh or zone segment",
			item: resourceItem{Type: "Zone", Name: "east"},
			want: "kri_z____east_",
		},
		{
			name: "type removed in 3.0 has no KRI",
			item: resourceItem{Type: "TrafficRoute", Mesh: "default", Name: "route-1"},
			want: "",
		},
		{
			name: "unknown type has no KRI",
			item: resourceItem{Type: "SomethingNew", Mesh: "default", Name: "x"},
			want: "",
		},
		{
			name: "empty name has no KRI",
			item: resourceItem{Type: "MeshTimeout", Mesh: "default"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kriOf(tt.item); got != tt.want {
				t.Errorf("kriOf(%s %s/%s) = %q, want %q", tt.item.Type, tt.item.Mesh, tt.item.Name, got, tt.want)
			}
		})
	}
}

// TestKriOfShortNames pins the ported short names against the Kuma 3.0
// descriptors so a regeneration cannot silently drift.
func TestKriOfShortNames(t *testing.T) {
	pinned := map[string]string{
		"Mesh":                      "m",
		"Dataplane":                 "dp",
		"Zone":                      "z",
		"MeshService":               "msvc",
		"MeshTimeout":               "mt",
		"MeshHTTPRoute":             "mhttpr",
		"MeshTrafficPermission":     "mtp",
		"MeshExternalService":       "extsvc",
		"MeshMultiZoneService":      "mzsvc",
		"MeshTrust":                 "mtrust",
		"MeshIdentity":              "mid",
		"MeshZoneAddress":           "mza",
		"MeshOPA":                   "mopa",
		"AccessRole":                "ar",
		"AccessAudit":               "aa",
		"AccessRoleBinding":         "arb",
		"MeshLoadBalancingStrategy": "mlbs",
		"MeshCircuitBreaker":        "mcb",
	}
	for typ, want := range pinned {
		if got := shortNames[typ]; got != want {
			t.Errorf("shortNames[%s] = %q, want %q", typ, got, want)
		}
	}
}

// TestKriOfFromRESTItem builds a resourceItem the way the audit does (JSON
// from the CP REST API) and checks the KRI carries the display name.
func TestKriOfFromRESTItem(t *testing.T) {
	raw := `{"type":"DataplaneOverview","mesh":"default","name":"web-0-x9f2b.kuma-system",` +
		`"labels":{"kuma.io/zone":"zone-1","kuma.io/display-name":"web-0","k8s.kuma.io/namespace":"kuma-system"}}`
	var it resourceItem
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatal(err)
	}
	want := "kri_dp_default_zone-1_kuma-system_web-0_"
	if got := kriOf(it); got != want {
		t.Errorf("kriOf = %q, want %q", got, want)
	}
}
