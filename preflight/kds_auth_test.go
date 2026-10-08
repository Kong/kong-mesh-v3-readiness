package preflight

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestKDSAuthFindings covers the KDS authentication settings 3.0 removes with
// the kmesh.multizone section: each patch is decoded onto a clean config
// through the real /config JSON keys, and the flagging conditions mirror the
// ones the 2.14 control plane itself deprecates on.
func TestKDSAuthFindings(t *testing.T) {
	const title = "KDS auth set under the removed kmesh.multizone settings"
	for _, tc := range []struct {
		name, patch string
		want        []string
	}{
		{
			"auth type cpToken", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"type":"cpToken"}}}}}}`,
			[]string{"kmesh.multizone.global.kds.auth.type=cpToken (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_TYPE)"},
		},
		{
			"auth type konnect", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"type":"konnect"}}}}}}`,
			[]string{"kmesh.multizone.global.kds.auth.type=konnect (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_TYPE)"},
		},
		{"auth type none is the default", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"type":"none"}}}}}}`, nil},
		{
			"issuer off", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"cpToken":{"enableIssuer":false}}}}}}}`,
			[]string{"kmesh.multizone.global.kds.auth.cpToken.enableIssuer=false (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_CP_TOKEN_ENABLE_ISSUER)"},
		},
		{"issuer on is the default", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"cpToken":{"enableIssuer":true}}}}}}}`, nil},
		{
			"secrets validator off", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"cpToken":{"validator":{"useSecrets":false}}}}}}}}`,
			[]string{"kmesh.multizone.global.kds.auth.cpToken.validator.useSecrets=false (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_CP_TOKEN_VALIDATOR_USE_SECRETS)"},
		},
		{
			"public keys", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"cpToken":{"validator":{"publicKeys":[{"kid":"1","key":"AAA"}]}}}}}}}}`,
			[]string{"kmesh.multizone.global.kds.auth.cpToken.validator.publicKeys set"},
		},
		{"empty public keys", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"cpToken":{"validator":{"publicKeys":[]}}}}}}}}`, nil},
		{
			"zone inline token", `{"kmesh":{"multizone":{"zone":{"kds":{"auth":{"cpTokenInline":"*****"}}}}}}`,
			[]string{"kmesh.multizone.zone.kds.auth.cpTokenInline set (KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_INLINE)"},
		},
		{
			"zone token path", `{"kmesh":{"multizone":{"zone":{"kds":{"auth":{"cpTokenPath":"/etc/kong-mesh/zone-token"}}}}}}`,
			[]string{"kmesh.multizone.zone.kds.auth.cpTokenPath=/etc/kong-mesh/zone-token (KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_PATH)"},
		},
		{
			"every setting at once", `{"kmesh":{"multizone":{"global":{"kds":{"auth":{"type":"cpToken","cpToken":{"enableIssuer":false,"validator":{"useSecrets":false,"publicKeys":[{"kid":"1"}]}}}}},"zone":{"kds":{"auth":{"cpTokenInline":"*****","cpTokenPath":"/t"}}}}}}`,
			[]string{
				"kmesh.multizone.global.kds.auth.type=cpToken (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_TYPE)",
				"kmesh.multizone.global.kds.auth.cpToken.enableIssuer=false (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_CP_TOKEN_ENABLE_ISSUER)",
				"kmesh.multizone.global.kds.auth.cpToken.validator.useSecrets=false (KMESH_MULTIZONE_GLOBAL_KDS_AUTH_CP_TOKEN_VALIDATOR_USE_SECRETS)",
				"kmesh.multizone.global.kds.auth.cpToken.validator.publicKeys set",
				"kmesh.multizone.zone.kds.auth.cpTokenInline set (KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_INLINE)",
				"kmesh.multizone.zone.kds.auth.cpTokenPath=/t (KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_PATH)",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg cpConfig
			if err := json.Unmarshal([]byte(tc.patch), &cfg); err != nil {
				t.Fatal(err)
			}
			a := &auditor{rep: &collector{}}
			a.addKDSAuthFindings(cfg, zoneRef(""))
			f, ok := findCollectorFinding(a.rep, blocker, cpConfigCategory, title)
			if tc.want == nil {
				if ok {
					t.Errorf("unexpected finding: %+v", f)
				}
				return
			}
			if !ok {
				t.Fatalf("finding not flagged; findings: %+v", a.rep.findings)
			}
			if got, want := strings.Join(f.examples, "\n"), strings.Join(tc.want, "\n"); got != want {
				t.Errorf("examples = %q, want %q", got, want)
			}
		})
	}
}

// TestKDSAuthFindingDetail: the finding's detail carries the Kuma replacement
// names, the leftover-variable startup abort and the 2.14.6 mirror caveat.
func TestKDSAuthFindingDetail(t *testing.T) {
	var cfg cpConfig
	if err := json.Unmarshal([]byte(`{"kmesh":{"multizone":{"global":{"kds":{"auth":{"type":"cpToken"}}}}}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	a := &auditor{rep: &collector{}}
	a.addKDSAuthFindings(cfg, zoneRef(""))
	f, ok := findCollectorFinding(a.rep, blocker, cpConfigCategory, "KDS auth set under the removed kmesh.multizone settings")
	if !ok {
		t.Fatalf("finding not flagged; findings: %+v", a.rep.findings)
	}
	for _, want := range []string{
		"KUMA_MULTIZONE_GLOBAL_KDS_AUTH_TYPE",
		"cpToken is called zoneToken",
		"KUMA_MULTIZONE_ZONE_KDS_AUTH_TOKEN_INLINE",
		"leftover aborts the 3.0 startup",
		"mirrors the effective values into both",
		"is deprecated, use",
	} {
		if !strings.Contains(f.detail, want) {
			t.Errorf("detail %q does not contain %q", f.detail, want)
		}
	}
	if f.doc != docKumaCPReference {
		t.Errorf("doc = %q, want %q", f.doc, docKumaCPReference)
	}
}

// TestKDSAuthFindingsMerged: a global and its zones share one finding, the
// zone-sourced examples qualified with the zone name.
func TestKDSAuthFindingsMerged(t *testing.T) {
	a := &auditor{rep: &collector{}}
	a.addKDSAuthFindings(cpConfig{}, zoneRef(""))
	if n := len(a.rep.findings); n != 0 {
		t.Fatalf("defaults produced %d findings, want 0", n)
	}
	var globalCfg, zoneCfg cpConfig
	if err := json.Unmarshal([]byte(`{"kmesh":{"multizone":{"global":{"kds":{"auth":{"type":"cpToken"}}}}}}`), &globalCfg); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"kmesh":{"multizone":{"zone":{"kds":{"auth":{"cpTokenInline":"*****"}}}}}}`), &zoneCfg); err != nil {
		t.Fatal(err)
	}
	a.addKDSAuthFindings(globalCfg, zoneRef(""))
	a.addKDSAuthFindings(zoneCfg, zoneRef("zone-1"))
	f, ok := findCollectorFinding(a.rep, blocker, cpConfigCategory, "KDS auth set under the removed kmesh.multizone settings")
	if !ok {
		t.Fatalf("finding not flagged; findings: %+v", a.rep.findings)
	}
	if len(f.examples) != 2 {
		t.Fatalf("examples = %v, want the global and the zone-1 one", f.examples)
	}
	if f.examples[1] != "zone zone-1: kmesh.multizone.zone.kds.auth.cpTokenInline set (KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_INLINE)" {
		t.Errorf("zone example not qualified: %q", f.examples[1])
	}
}

// findCollectorFinding finds the merged finding with the given key in a
// collector, before it is rendered into a Report model.
func findCollectorFinding(r *collector, sev severity, category, title string) (rawFinding, bool) {
	for _, f := range r.findings {
		if f.severity == sev && f.category == category && f.title == title {
			return f, true
		}
	}
	return rawFinding{}, false
}
