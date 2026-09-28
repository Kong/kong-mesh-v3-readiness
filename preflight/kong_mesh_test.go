package preflight

import (
	"net/http"
	"strings"
	"testing"
)

// TestOPAPolicyRemoved: any legacy OPAPolicy is a blocker, and an OSS Kuma CP
// that 404s the enterprise collection is not a coverage gap.
func TestOPAPolicyRemoved(t *testing.T) {
	const title = "OPAPolicy (removed in 3.0)"
	m := auditResponses(t, map[string]string{
		"/opa-policies": listBody(t, map[string]any{"type": "OPAPolicy", "mesh": "default", "name": "legacy-opa"}),
	})
	f, ok := findFinding(m, "blocker", categoryRemovedPolicy, title)
	if !ok {
		t.Fatalf("OPAPolicy not flagged; findings: %+v", m.Findings)
	}
	if f.Doc != docMeshOPA {
		t.Errorf("doc = %q, want %q", f.Doc, docMeshOPA)
	}

	m = auditWithNotFound(t, nil, "/opa-policies", "/meshopas", "/access-roles", "/accessaudits")
	if len(m.Coverage) != 0 {
		t.Errorf("OSS 404s produced coverage gaps: %+v", m.Coverage)
	}
}

// TestMeshOPAPolicyChecks covers MeshOPA going through the generic targetRef
// checks (kind, proxyTypes, name) and the flat DataSource shape check.
func TestMeshOPAPolicyChecks(t *testing.T) {
	typed := map[string]any{"type": "InsecureInline", "insecureInline": map[string]any{"value": "package x"}}
	for _, tc := range []struct {
		name, category, title string
		spec                  map[string]any
		want                  bool
	}{
		{
			"top-level MeshService", "Top-level targetRef kind", "MeshOPA top-level targetRef.kind=MeshService",
			map[string]any{"targetRef": map[string]any{"kind": "MeshService", "name": "backend"}},
			true,
		},
		{
			"Dataplane by name", "Reference by name", "MeshOPA references a resource by name",
			map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "name": "dp-1"}},
			true,
		},
		{
			"proxyTypes", "targetRef proxyTypes", "MeshOPA scoped to sidecars with targetRef.proxyTypes",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh", "proxyTypes": []any{"Sidecar"}}},
			true,
		},
		{
			"flat agentConfig", "MeshOPA data source", "MeshOPA uses the removed flat DataSource shape",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "default": map[string]any{"agentConfig": map[string]any{"secret": "opa-config"}}},
			true,
		},
		{
			"flat rego inlineString", "MeshOPA data source", "MeshOPA uses the removed flat DataSource shape",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "default": map[string]any{"appendPolicies": []any{
				map[string]any{"rego": typed}, map[string]any{"rego": map[string]any{"inlineString": "package x"}},
			}}},
			true,
		},
		{
			"typed data sources", "MeshOPA data source", "MeshOPA uses the removed flat DataSource shape",
			map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "default": map[string]any{
				"agentConfig":    map[string]any{"type": "Secret", "secretRef": map[string]any{"kind": "Secret", "name": "opa-config"}},
				"appendPolicies": []any{map[string]any{"rego": typed}},
			}},
			false,
		},
		{
			"Dataplane by labels", "Reference by name", "MeshOPA references a resource by name",
			map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "labels": map[string]any{"app": "backend"}}},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/meshopas": policyBody(t, "MeshOPA", tc.spec, nil)})
			if _, got := findFinding(m, "blocker", tc.category, tc.title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

func accessRoleBody(t *testing.T, rules ...map[string]any) string {
	t.Helper()
	return listBody(t, map[string]any{"type": "AccessRole", "name": "team-a", "rules": rules})
}

// TestAccessRoleQualifiers covers the AccessRole `when[]` qualifiers 3.0 rejects
// on write, and the info-level name match that 3.0 narrows.
func TestAccessRoleQualifiers(t *testing.T) {
	rule := func(when ...map[string]any) map[string]any {
		return map[string]any{"types": []any{"MeshTimeout"}, "mesh": "default", "access": []any{"CREATE"}, "when": when}
	}
	tref := func(kind, name string) map[string]any {
		r := map[string]any{"kind": kind}
		if name != "" {
			r["name"] = name
		}
		return r
	}
	for _, tc := range []struct {
		name, severity, title string
		when                  map[string]any
		want                  bool
	}{
		{"top-level MeshService", "blocker", "AccessRole when[].targetRef.kind=MeshService", map[string]any{"targetRef": tref("MeshService", "backend")}, true},
		{"top-level MeshSubset", "blocker", "AccessRole when[].targetRef.kind=MeshSubset", map[string]any{"targetRef": map[string]any{"kind": "MeshSubset", "tags": map[string]any{"version": "v1"}}}, true},
		{"top-level Mesh", "blocker", "AccessRole when[].targetRef.kind=Mesh", map[string]any{"targetRef": tref("Mesh", "")}, false},
		{"from", "blocker", "AccessRole qualifier uses `from`", map[string]any{"from": map[string]any{"targetRef": tref("Mesh", "")}}, true},
		{"to MeshServiceSubset", "blocker", "AccessRole when[].to.targetRef.kind=MeshServiceSubset", map[string]any{"to": map[string]any{"targetRef": tref("MeshServiceSubset", "backend")}}, true},
		{"to MeshGateway", "blocker", "AccessRole when[].to.targetRef.kind=MeshGateway", map[string]any{"to": map[string]any{"targetRef": tref("MeshGateway", "gw")}}, true},
		{"to MeshService", "blocker", "AccessRole when[].to.targetRef.kind=MeshService", map[string]any{"to": map[string]any{"targetRef": tref("MeshService", "")}}, false},
		{"selectors", "blocker", "AccessRole qualifier uses sources, destinations or selectors", map[string]any{"selectors": map[string]any{"match": map[string]any{"kuma.io/service": "*"}}}, true},
		{"empty sources", "blocker", "AccessRole qualifier uses sources, destinations or selectors", map[string]any{"sources": map[string]any{}}, true},
		{"dpToken only", "blocker", "AccessRole qualifier uses sources, destinations or selectors", map[string]any{"dpToken": map[string]any{"tags": []any{}}}, false},
		{"Dataplane by name", "info", "AccessRole qualifier matches a targetRef by name", map[string]any{"targetRef": tref("Dataplane", "dp-1")}, true},
		{"to MeshService by name", "info", "AccessRole qualifier matches a targetRef by name", map[string]any{"to": map[string]any{"targetRef": tref("MeshService", "backend")}}, true},
		{"rejected kind is not also a name match", "info", "AccessRole qualifier matches a targetRef by name", map[string]any{"targetRef": tref("MeshService", "backend")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/access-roles": accessRoleBody(t, rule(tc.when))})
			if _, got := findFinding(m, tc.severity, categoryAccessRoles, tc.title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestRBACRemovedTypes: AccessRole and AccessAudit rules naming a kind 3.0 no
// longer registers are blockers, listing every removed kind once, sorted.
func TestRBACRemovedTypes(t *testing.T) {
	types := []any{"TrafficPermission", "MeshTimeout", "OPAPolicy", "ZoneIngress", "TrafficPermission"}
	m := auditResponses(t, map[string]string{
		"/access-roles": accessRoleBody(t, map[string]any{"types": types, "mesh": "default", "access": []any{"CREATE"}}),
		"/accessaudits": listBody(t, map[string]any{"type": "AccessAudit", "name": "audit", "rules": []any{
			map[string]any{"types": []any{"MeshGlobalRateLimit", "MeshGateway"}, "accessAll": true},
		}}),
	})
	for _, tc := range []struct{ title, example string }{
		{"AccessRole rule types name a kind removed in 3.0", "team-a (OPAPolicy, TrafficPermission, ZoneIngress)"},
		{"AccessAudit rule types name a kind removed in 3.0", "audit (MeshGateway, MeshGlobalRateLimit)"},
	} {
		f, ok := findFinding(m, "blocker", categoryAccessRoles, tc.title)
		if !ok {
			t.Errorf("%q not flagged; findings: %+v", tc.title, m.Findings)
			continue
		}
		if len(f.Examples) != 1 || f.Examples[0] != tc.example {
			t.Errorf("%q examples = %v, want [%s]", tc.title, f.Examples, tc.example)
		}
	}
}

// TestRemovedKindNamesCoversCatalogs keeps the types[] set in lockstep with the
// removed-kind catalogs it is built from.
func TestRemovedKindNamesCoversCatalogs(t *testing.T) {
	names := removedKindNames()
	for _, lt := range legacyMeshScoped {
		if !names[lt.kind] {
			t.Errorf("legacy kind %s missing", lt.kind)
		}
	}
	for _, rp := range removedEnterprisePolicies {
		if !names[rp.kind] {
			t.Errorf("enterprise kind %s missing", rp.kind)
		}
	}
	for _, k := range []string{"MeshTrafficPermission", "MeshOPA", "Dataplane", "AccessRole"} {
		if names[k] {
			t.Errorf("kept kind %s reported as removed", k)
		}
	}
}

// TestRBACMeshFilter: with --mesh, a rule pinned to another mesh is skipped, but
// a rule with no mesh (global types) still applies.
func TestRBACMeshFilter(t *testing.T) {
	c := &auditor{meshFilter: "default", rep: &collector{}}
	rules := []rbacRule{{Types: []string{"TrafficRoute"}, Mesh: "other"}, {Types: []string{"ZoneEgress"}}}
	c.checkRBACRules("AccessRole", rules, removedKindNames(), "team-a")
	if len(c.rep.findings) != 1 || !strings.HasSuffix(c.rep.findings[0].examples[0], "(ZoneEgress)") {
		t.Fatalf("findings = %+v, want one ZoneEgress types finding", c.rep.findings)
	}
}

// TestRBACForbiddenIsGap: a token without RBAC read access must not pass the
// AccessRole checks as clean.
func TestRBACForbiddenIsGap(t *testing.T) {
	m := auditResponsesFunc(t, func(path string) (string, int, bool) {
		if path == "/access-roles" {
			return `{"status":403}`, http.StatusForbidden, true
		}
		return "", 0, false
	})
	found := false
	for _, g := range m.Coverage {
		found = found || g.Path == "/access-roles"
	}
	if !found || m.Status != StatusInconclusive {
		t.Errorf("gaps = %+v, status = %q; want an /access-roles gap and inconclusive", m.Coverage, m.Status)
	}
}
