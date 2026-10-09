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
			name: "mesh resource is stored under NoMesh",
			item: resourceItem{Type: "Mesh", Name: "default"},
			want: "kri_m____default_",
		},
		{
			name: "name with an underscore is not KRI-addressable",
			item: resourceItem{Type: "MeshService", Mesh: "default", Name: "My_Service"},
			want: "",
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

// TestKriOfShortNames pins every ported short name (a typo or a regeneration
// against wrong descriptors would ship an unresolvable KRI for a whole type)
// and keeps the table consistent with the audit's own type catalogs: every
// kind the audit can emit as a kept resource must have a short name, and no
// kind removed in 3.0 may (3.0 registers neither its type nor its short
// name).
func TestKriOfShortNames(t *testing.T) {
	pinned := map[string]string{
		"Mesh":                      "m",
		"Dataplane":                 "dp",
		"Zone":                      "z",
		"MeshService":               "msvc",
		"MeshExternalService":       "extsvc",
		"MeshMultiZoneService":      "mzsvc",
		"MeshTrust":                 "mtrust",
		"MeshIdentity":              "mid",
		"MeshZoneAddress":           "mza",
		"MeshAccessLog":             "mal",
		"MeshCircuitBreaker":        "mcb",
		"MeshFaultInjection":        "mfi",
		"MeshHealthCheck":           "mhc",
		"MeshHTTPRoute":             "mhttpr",
		"MeshLoadBalancingStrategy": "mlbs",
		"MeshMetric":                "mm",
		"MeshPassthrough":           "mp",
		"MeshProxyPatch":            "mpp",
		"MeshRateLimit":             "mrl",
		"MeshRetry":                 "mr",
		"MeshTCPRoute":              "mtcpr",
		"MeshTimeout":               "mt",
		"MeshTLS":                   "mtls",
		"MeshTrace":                 "mtr",
		"MeshTrafficPermission":     "mtp",
		"MeshOPA":                   "mopa",
		"AccessRole":                "ar",
		"AccessAudit":               "aa",
		"AccessRoleBinding":         "arb",
	}
	if len(shortNames) != len(pinned) {
		t.Errorf("shortNames has %d entries, test pins %d — sync the table and the pin", len(shortNames), len(pinned))
	}
	for typ, want := range pinned {
		if got := shortNames[typ]; got != want {
			t.Errorf("shortNames[%s] = %q, want %q", typ, got, want)
		}
	}

	for _, lt := range legacyMeshScoped {
		if _, ok := shortNames[lt.kind]; ok {
			t.Errorf("removed kind %s must not have a KRI short name", lt.kind)
		}
	}
	for _, rp := range removedEnterprisePolicies {
		if _, ok := shortNames[rp.kind]; ok {
			t.Errorf("removed enterprise kind %s must not have a KRI short name", rp.kind)
		}
	}
	for _, k := range removedCoreKinds {
		if _, ok := shortNames[k]; ok {
			t.Errorf("removed core kind %s must not have a KRI short name", k)
		}
	}

	// EXC:FILE011:every kept kind the audit lists must resolve — policies, RBAC, core collections
	auditedKinds := []string{
		"MeshTrafficPermission", "MeshFaultInjection", "MeshTLS", "MeshAccessLog",
		"MeshRateLimit", "MeshCircuitBreaker", "MeshTimeout", "MeshHTTPRoute",
		"MeshTCPRoute", "MeshRetry", "MeshHealthCheck", "MeshLoadBalancingStrategy",
		"MeshProxyPatch", "MeshMetric", "MeshTrace", "MeshPassthrough",
		"MeshOPA", "AccessRole", "AccessAudit", "AccessRoleBinding",
		"Mesh", "Dataplane", "Zone", "MeshService", "MeshExternalService",
		"MeshMultiZoneService", "MeshZoneAddress", "MeshTrust", "MeshIdentity",
	}
	for _, kind := range auditedKinds {
		if _, ok := shortNames[kind]; !ok {
			t.Errorf("audited kind %s has no KRI short name", kind)
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
