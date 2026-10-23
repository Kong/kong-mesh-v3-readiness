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
			name: "name with a space is not KRI-addressable",
			item: resourceItem{Type: "MeshTimeout", Mesh: "default", Name: "a name"},
			want: "",
		},
		{
			name: "name with a slash is not KRI-addressable",
			item: resourceItem{Type: "MeshTimeout", Mesh: "default", Name: "a/b"},
			want: "",
		},
		{
			name: "name with a parenthesis is not KRI-addressable",
			item: resourceItem{Type: "MeshTimeout", Mesh: "default", Name: "paren(name)"},
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

// TestExampleAnnotations pins that an example holding a KRI is exactly the KRI,
// whatever note or system tag the check offers, while a legacy display string
// (a name with "_" has no KRI) keeps its note.
func TestExampleAnnotations(t *testing.T) {
	system := map[string]string{policyRoleLabel: "system"}
	tests := []struct {
		name         string
		item         resourceItem
		wantRef      string
		wantQualNote string
	}{
		{
			name:         "KRI stays bare",
			item:         resourceItem{Type: "Dataplane", Mesh: "default", Name: "dp-1"},
			wantRef:      "kri_dp_default___dp-1_",
			wantQualNote: "kri_dp_default___dp-1_",
		},
		{
			name:         "system KRI stays bare",
			item:         resourceItem{Type: "MeshTimeout", Mesh: "default", Name: "mesh-timeout-all-default", Labels: system},
			wantRef:      "kri_mt_default___mesh-timeout-all-default_",
			wantQualNote: "kri_mt_default___mesh-timeout-all-default_",
		},
		{
			name:         "legacy display string keeps the note",
			item:         resourceItem{Type: "Dataplane", Mesh: "default", Name: "dp_1"},
			wantRef:      "default/dp_1",
			wantQualNote: "default/dp_1 (kuma-dp 2.5.0)",
		},
		{
			name:         "system resource with a space in its name is a legacy string",
			item:         resourceItem{Type: "MeshTimeout", Mesh: "default", Name: "a name", Labels: system},
			wantRef:      "default/a name (system — CP-managed, update before 3.0)",
			wantQualNote: "default/a name (kuma-dp 2.5.0)",
		},
		{
			name:         "system legacy display string keeps the tag",
			item:         resourceItem{Type: "TrafficPermission", Mesh: "default", Name: "allow-all", Labels: system},
			wantRef:      "default/allow-all (system — CP-managed, update before 3.0)",
			wantQualNote: "default/allow-all (kuma-dp 2.5.0)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := (&auditor{}).ref(tc.item); got != tc.wantRef {
				t.Errorf("ref = %q, want %q", got, tc.wantRef)
			}
			if got := qualifiedNote(tc.item, "kuma-dp 2.5.0"); got != tc.wantQualNote {
				t.Errorf("qualifiedNote = %q, want %q", got, tc.wantQualNote)
			}
		})
	}
}

func TestIsKRI(t *testing.T) {
	for s, want := range map[string]bool{
		"kri_dp_default___dp-1_":     true,
		"kri_m____default_":          true,
		"kri_m___default_":           false,
		"kri_dp_default___dp-1":      false,
		"default/kri_dp_a_b_c_d_":    false,
		"kri_x":                      false,
		"kri_dp_default___dp-1_ (n)": false,
		"control plane (2.14.6)":     false,
	} {
		if got := isKRI(s); got != want {
			t.Errorf("isKRI(%q) = %v, want %v", s, got, want)
		}
	}
}
