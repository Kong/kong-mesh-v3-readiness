package preflight

import (
	"encoding/json"
	"testing"
)

// emptyMatchTitle is the finding title checkPermissionMatches records.
const emptyMatchTitle = "MeshTrafficPermission has a match entry without spiffeID or sni"

// permissionItem builds one stored policy as the CP API returns it and decodes
// it through the real resourceItem envelope. The universal shape carries plain
// metadata; the Kubernetes shape adds orchestrator labels.
func permissionItem(t *testing.T, typ, labels, spec string) resourceItem {
	t.Helper()
	raw := `{"type":"` + typ + `","mesh":"default","name":"mtp-1"` + labels + `,"spec":` + spec + `}`
	var it resourceItem
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatalf("item envelope: %v", err)
	}
	return it
}

// TestPermissionEmptyMatch covers stored MeshTrafficPermission rules whose
// default action entries set neither spiffeID nor sni. Write-time validation
// only rejects new resources: a 2.14 store can already hold empty entries, and
// a universal KDS apply can bypass validation, so the scan must flag them.
func TestPermissionEmptyMatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels string
		spec   string
		block  bool
	}{
		{"empty deny entry", "", `{"rules":[{"default":{"deny":[{}]}}]}`, true},
		{"empty allow entry", "", `{"rules":[{"default":{"allow":[{}]}}]}`, true},
		{"empty shadow-deny entry", "", `{"rules":[{"default":{"allowWithShadowDeny":[{}]}}]}`, true},
		{"null entry", "", `{"rules":[{"default":{"deny":[null]}}]}`, true},
		{"null spiffeID without sni", "", `{"rules":[{"default":{"deny":[{"spiffeID":null}]}}]}`, true},
		{"empty entry in second rule", "", `{"rules":[{"default":{"deny":[{"sni":{"type":"Exact","value":"example.com"}}]}},{"default":{"allow":[{}]}}]}`, true},
		{"valid spiffeID", "", `{"rules":[{"default":{"deny":[{"spiffeID":{"type":"Exact","value":"spiffe://trust.domain/service"}}]}}]}`, false},
		{"valid prefix spiffeID", "", `{"rules":[{"default":{"allow":[{"spiffeID":{"type":"Prefix","value":"spiffe://trust.domain"}}]}}]}`, false},
		{"valid entry before empty in same list", "", `{"rules":[{"default":{"allow":[{"spiffeID":{"type":"Prefix","value":"spiffe://default.default.mesh.local"}},{}]}}]}`, true},
		{"stored system permission", `,"labels":{"kuma.io/policy-role":"system"}`, `{"rules":[{"default":{"allow":[{"spiffeID":{"type":"Prefix","value":"spiffe://default.default.mesh.local"}}]}}]}`, false},
		{"valid sni", "", `{"rules":[{"default":{"allow":[{"sni":{"type":"Exact","value":"example.com"}}]}}]}`, false},
		{"null spiffeID with sni", "", `{"rules":[{"default":{"deny":[{"spiffeID":null,"sni":{"type":"Exact","value":"example.com"}}]}}]}`, false},
		{"empty action arrays", "", `{"rules":[{"default":{"allow":[],"allowWithShadowDeny":[],"deny":[]}}]}`, false},
		{"null action fields", "", `{"rules":[{"default":{"allow":null,"deny":null}}]}`, false},
		{"empty array beside valid predicate", "", `{"rules":[{"default":{"allow":[],"deny":[{"sni":{"type":"Exact","value":"example.com"}}]}}]}`, false},
		{"absent default", "", `{"rules":[{}]}`, false},
		{"absent rules", "", `{"targetRef":{"kind":"Mesh"}}`, false},
		{"kubernetes envelope", `,"labels":{"k8s.kuma.io/namespace":"team-a"}`, `{"rules":[{"default":{"deny":[{}]}}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := auditor{rep: &collector{}}
			a.checkNewPolicy(permissionItem(t, "MeshTrafficPermission", tc.labels, tc.spec))
			found := false
			for _, finding := range a.rep.findings {
				if finding.title == emptyMatchTitle {
					found = true
					if finding.severity != blocker {
						t.Fatalf("empty-match finding has severity %q", finding.severity)
					}
				}
			}
			if found != tc.block {
				t.Fatalf("empty-match blocker = %v, want %v", found, tc.block)
			}
			if a.rep.parseErrors != 0 {
				t.Fatalf("well-formed spec counted %d parse errors", a.rep.parseErrors)
			}
		})
	}
}

// TestPermissionOtherKindKeepsRules proves the guard stays type-gated: another
// policy with a `rules` section produces no empty-match finding and no parse
// error.
func TestPermissionOtherKindKeepsRules(t *testing.T) {
	a := auditor{rep: &collector{}}
	a.checkNewPolicy(permissionItem(t, "MeshHTTPRoute", "", `{"rules":[{"matches":[{"path":{"type":"Exact","value":"/"}}]}]}`))
	for _, finding := range a.rep.findings {
		if finding.title == emptyMatchTitle {
			t.Fatal("MeshHTTPRoute rules produced an empty-match finding")
		}
	}
	if a.rep.parseErrors != 0 {
		t.Fatalf("MeshHTTPRoute rules counted %d parse errors", a.rep.parseErrors)
	}
}

// TestPermissionMatchMalformedIsInconclusive follows unmarshalSpec: a malformed
// rules section must count a parse error and mark the audit incomplete, never
// pass silently.
func TestPermissionMatchMalformedIsInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
	}{
		{"action is not an array", `{"rules":[{"default":{"allow":"everyone"}}]}`},
		{"entry is not an object", `{"rules":[{"default":{"deny":["foo"]}}]}`},
		{"spiffeID is not an object", `{"rules":[{"default":{"deny":[{"spiffeID":"spiffe://trust.domain"}]}}]}`},
		{"default is not an object", `{"rules":[{"default":[]}]}`},
		{"rules is not an array", `{"rules":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := auditor{rep: &collector{}}
			a.checkNewPolicy(permissionItem(t, "MeshTrafficPermission", "", tc.spec))
			if a.rep.parseErrors != 1 || !a.rep.incomplete() {
				t.Fatalf("malformed spec: parseErrors = %d, incomplete = %v", a.rep.parseErrors, a.rep.incomplete())
			}
			for _, finding := range a.rep.findings {
				if finding.title == emptyMatchTitle {
					t.Fatal("malformed spec produced an empty-match finding")
				}
			}
		})
	}
}
