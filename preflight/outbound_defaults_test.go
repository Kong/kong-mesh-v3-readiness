package preflight

import (
	"maps"
	"strings"
	"testing"
)

const (
	categoryOutboundDefaults = "Outbound defaults"

	titleUniversalDeny     = "Universal Dataplanes have no reachableBackends"
	titleKubernetesDeny    = "Kubernetes dataplanes have no reachableBackends"
	titleNoMeshPassthrough = "Mesh has no MeshPassthrough policy"
)

// overview builds one /dataplanes+insights item: a DataplaneOverview nests the
// Dataplane spec under "dataplane", alongside the insight.
func overview(name string, labels map[string]any, networking map[string]any, metadata map[string]any) map[string]any {
	it := map[string]any{
		"type":      "DataplaneOverview",
		"mesh":      "default",
		"name":      name,
		"dataplane": map[string]any{"networking": networking},
	}
	if labels != nil {
		it["labels"] = labels
	}
	if metadata != nil {
		it["dataplaneInsight"] = map[string]any{"metadata": metadata}
	}
	return it
}

// tproxySpec is the legacy (pre-3.0) transparent-proxy declaration: redirect
// ports on the Dataplane spec.
func tproxySpec(extra map[string]any) map[string]any {
	tp := map[string]any{"redirectPortInbound": 15006, "redirectPortOutbound": 15001}
	maps.Copy(tp, extra)
	return map[string]any{"transparentProxying": tp}
}

// permissiveConfigJSON is readyConfigJSON with the 2.14 outbound default left
// permissive, which is what makes the outbound-deny checks apply at all.
var permissiveConfigJSON = strings.Replace(readyConfigJSON,
	`"defaults": {"restrictOutbound": true}`, `"defaults": {"restrictOutbound": false}`, 1)

func auditOverviews(t *testing.T, items ...map[string]any) Report {
	t.Helper()
	return auditResponses(t, map[string]string{
		"/config":              permissiveConfigJSON,
		"/dataplanes+insights": listBody(t, items...),
	})
}

var (
	universalLabels  = map[string]any{"kuma.io/env": "universal"}
	kubernetesLabels = map[string]any{"kuma.io/env": "kubernetes"}
)

// Kubernetes and Universal are separate findings because the remediation differs.
func TestOutboundDenyFlagsProxiesWithNoReachableBackends(t *testing.T) {
	cases := []struct {
		name  string
		item  map[string]any
		title string
	}{
		{
			name:  "universal, redirect ports on the spec",
			item:  overview("dp-1", universalLabels, tproxySpec(nil), nil),
			title: titleUniversalDeny,
		},
		{
			name:  "kubernetes, redirect ports on the spec",
			item:  overview("dp-1", kubernetesLabels, tproxySpec(nil), nil),
			title: titleKubernetesDeny,
		},
		{
			name: "transparent proxy reported only through kuma-dp metadata",
			item: overview("dp-1", universalLabels, map[string]any{}, map[string]any{
				"transparentProxy": map[string]any{"redirect": map[string]any{"outbound": map[string]any{"enabled": true}}},
			}),
			title: titleUniversalDeny,
		},
		{
			name:  "unlabeled proxy counts as Universal",
			item:  overview("dp-1", nil, tproxySpec(nil), nil),
			title: titleUniversalDeny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditOverviews(t, tc.item)
			f, ok := findFinding(m, "blocker", categoryOutboundDefaults, tc.title)
			if !ok {
				t.Fatalf("missing finding %q\nfindings: %+v", tc.title, m.Findings)
			}
			if f.Count != 1 {
				t.Errorf("count = %d, want 1", f.Count)
			}
			if !strings.Contains(f.Detail, "1 of 1") {
				t.Errorf("detail does not report the N-of-M tally: %q", f.Detail)
			}
			if f.Doc != docReachableBackends {
				t.Errorf("doc = %q, want %q", f.Doc, docReachableBackends)
			}
			if m.Status != StatusBlockers {
				t.Errorf("status = %q, want %q", m.Status, StatusBlockers)
			}
		})
	}
}

func TestOutboundDenySkipsProxiesThatKeepOutbounds(t *testing.T) {
	cases := []struct {
		name string
		item map[string]any
	}{
		{
			name: "explicitly empty reachableBackends is a deliberate deny",
			item: overview("dp-1", universalLabels, tproxySpec(map[string]any{
				"reachableBackends": map[string]any{"refs": []any{}},
			}), nil),
		},
		{
			name: "reachableBackends names its destinations",
			item: overview("dp-1", universalLabels, tproxySpec(map[string]any{
				"reachableBackends": map[string]any{"refs": []any{map[string]any{"kind": "MeshService", "name": "backend"}}},
			}), nil),
		},
		{
			name: "an outbound with a backendRef short-circuits resolution",
			item: func() map[string]any {
				net := tproxySpec(nil)
				net["outbound"] = []any{map[string]any{
					"port":       10001,
					"backendRef": map[string]any{"kind": "MeshService", "name": "backend", "port": 80},
				}}
				return overview("dp-1", universalLabels, net, nil)
			}(),
		},
		{
			name: "no transparent proxying at all",
			item: overview("dp-1", universalLabels, map[string]any{"inbound": []any{map[string]any{"port": 8080}}}, nil),
		},
		{
			name: "kuma-dp reports transparent proxying off, overriding stale spec ports",
			item: overview("dp-1", universalLabels, tproxySpec(nil), map[string]any{
				"transparentProxy": map[string]any{"redirect": map[string]any{
					"inbound":  map[string]any{"enabled": false},
					"outbound": map[string]any{"enabled": false},
				}},
			}),
		},
		{
			name: "builtin gateway cannot exist on 3.0 at all",
			item: func() map[string]any {
				net := tproxySpec(nil)
				net["gateway"] = map[string]any{"type": "BUILTIN"}
				return overview("dp-1", universalLabels, net, nil)
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditOverviews(t, tc.item)
			for _, title := range []string{titleUniversalDeny, titleKubernetesDeny} {
				if _, ok := findFinding(m, "blocker", categoryOutboundDefaults, title); ok {
					t.Errorf("wrongly flagged %q\nfindings: %+v", title, m.Findings)
				}
			}
		})
	}
}

func TestOutboundDenyReportsSummaryNotPerProxy(t *testing.T) {
	items := []map[string]any{
		overview("safe", universalLabels, tproxySpec(map[string]any{
			"reachableBackends": map[string]any{"refs": []any{}},
		}), nil),
	}
	for _, n := range []string{"dp-1", "dp-2", "dp-3"} {
		items = append(items, overview(n, universalLabels, tproxySpec(nil), nil))
	}
	m := auditOverviews(t, items...)
	f, ok := findFinding(m, "blocker", categoryOutboundDefaults, titleUniversalDeny)
	if !ok {
		t.Fatalf("missing finding %q\nfindings: %+v", titleUniversalDeny, m.Findings)
	}
	if f.Count != 3 {
		t.Errorf("count = %d, want 3", f.Count)
	}
	if !strings.Contains(f.Detail, "3 of 4") {
		t.Errorf("detail does not report the N-of-M tally: %q", f.Detail)
	}
	if len(f.Examples) != 3 {
		t.Errorf("examples = %v, want the three affected proxies", f.Examples)
	}
}

func TestOutboundDenyNotConcludedFromCoverageGap(t *testing.T) {
	m := auditWithNotFound(t, map[string]string{"/config": permissiveConfigJSON}, "/dataplanes+insights")
	for _, title := range []string{titleUniversalDeny, titleKubernetesDeny} {
		if _, ok := findFinding(m, "blocker", categoryOutboundDefaults, title); ok {
			t.Errorf("finding %q concluded from an unread collection\nfindings: %+v", title, m.Findings)
		}
	}
	if m.Status != StatusInconclusive {
		t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
	}
}

func meshItem(passthrough *bool) map[string]any {
	it := map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}}
	if passthrough != nil {
		it["networking"] = map[string]any{"outbound": map[string]any{"passthrough": *passthrough}}
	}
	return it
}

func TestPassthroughDefaultFlagsMeshWithNoPolicy(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/config":              permissiveConfigJSON,
		"/meshes":              listBody(t, meshItem(nil)),
		"/dataplanes+insights": listBody(t, overview("dp-1", universalLabels, tproxySpec(nil), nil)),
	})
	f, ok := findFinding(m, "blocker", categoryOutboundDefaults, titleNoMeshPassthrough)
	if !ok {
		t.Fatalf("missing finding %q\nfindings: %+v", titleNoMeshPassthrough, m.Findings)
	}
	if f.Count != 1 || !strings.Contains(f.Detail, "1 of 1") {
		t.Errorf("count/detail = %d/%q, want 1 and a 1-of-1 tally", f.Count, f.Detail)
	}
	if f.Doc != docMeshPassthrough {
		t.Errorf("doc = %q, want %q", f.Doc, docMeshPassthrough)
	}
	if len(f.Examples) != 1 || f.Examples[0] != "default" {
		t.Errorf("examples = %v, want [default]", f.Examples)
	}
}

func TestPassthroughDefaultSkipsUnaffectedMeshes(t *testing.T) {
	passthroughOff := false
	cases := []struct {
		name      string
		responses map[string]string
		notFound  []string
	}{
		{
			name: "mesh already has a MeshPassthrough",
			responses: map[string]string{
				"/config":              permissiveConfigJSON,
				"/meshes":              listBody(t, meshItem(nil)),
				"/dataplanes+insights": listBody(t, overview("dp-1", universalLabels, tproxySpec(nil), nil)),
				"/meshpassthroughs": listBody(t, map[string]any{
					"type": "MeshPassthrough", "mesh": "default", "name": "allow-external",
					"spec": map[string]any{"targetRef": map[string]any{"kind": "Mesh"}},
				}),
			},
		},
		{
			name: "mesh already turns passthrough off",
			responses: map[string]string{
				"/config":              permissiveConfigJSON,
				"/meshes":              listBody(t, meshItem(&passthroughOff)),
				"/dataplanes+insights": listBody(t, overview("dp-1", universalLabels, tproxySpec(nil), nil)),
			},
		},
		{
			name:      "mesh has no transparent-proxy proxies",
			responses: map[string]string{"/config": permissiveConfigJSON, "/meshes": listBody(t, meshItem(nil))},
		},
		{
			name:      "MeshPassthrough collection could not be read",
			responses: map[string]string{"/config": permissiveConfigJSON, "/meshes": listBody(t, meshItem(nil))},
			notFound:  []string{"/meshpassthroughs"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditWithNotFound(t, tc.responses, tc.notFound...)
			if _, ok := findFinding(m, "blocker", categoryOutboundDefaults, titleNoMeshPassthrough); ok {
				t.Errorf("wrongly flagged %q\nfindings: %+v", titleNoMeshPassthrough, m.Findings)
			}
		})
	}
}

// A control plane already set to true denies this traffic today, so the upgrade
// changes nothing for a proxy without reachableBackends: it drops to info with a
// recommendation. The mesh missing a MeshPassthrough stays a blocker in the
// present tense, and the note about the coming change goes away.
func TestRestrictedControlPlaneStillVerifiesReachableBackends(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/meshes":              listBody(t, meshItem(nil)),
		"/dataplanes+insights": listBody(t, overview("dp-1", universalLabels, tproxySpec(nil), nil)),
	})
	if m.Status != StatusBlockers {
		t.Fatalf("status = %q, want %q\nfindings: %+v", m.Status, StatusBlockers, m.Findings)
	}
	for _, tc := range []struct{ sev, title string }{
		{SeverityInfo, titleUniversalDeny},
		{"blocker", titleNoMeshPassthrough},
	} {
		f, ok := findFinding(m, tc.sev, categoryOutboundDefaults, tc.title)
		if !ok {
			t.Fatalf("missing %s finding %q\nfindings: %+v", tc.sev, tc.title, m.Findings)
		}
		if !strings.Contains(f.Detail, "already `true` here") {
			t.Errorf("finding %q keeps the future-tense framing: %q", tc.title, f.Detail)
		}
	}
	if _, ok := findFinding(m, SeverityInfo, cpConfigCategory, "Default outbound changes in 3.0"); ok {
		t.Errorf("a control plane that already decided must not be told the default changes\nfindings: %+v", m.Findings)
	}
}

// The switch is reported as info, not a blocker: /config serves only the
// effective value, so pinning an explicit `false` could never clear a blocker.
func TestOutboundDefaultChangeReportedAsInfo(t *testing.T) {
	for _, tc := range []struct{ name, config, wantExample string }{
		{"permissive", permissiveConfigJSON, "defaults.restrictOutbound=false"},
		{"switch absent", strings.Replace(readyConfigJSON, `"defaults": {"restrictOutbound": true},`, "", 1), "defaults.restrictOutbound=unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/config": tc.config})
			f, ok := findFinding(m, SeverityInfo, cpConfigCategory, "Default outbound changes in 3.0")
			if !ok {
				t.Fatalf("missing info finding\nfindings: %+v", m.Findings)
			}
			if len(f.Examples) != 1 || f.Examples[0] != tc.wantExample {
				t.Errorf("examples = %v, want [%s]", f.Examples, tc.wantExample)
			}
			// Info alone must not gate: an otherwise-ready estate stays clean.
			if m.Status != StatusClean {
				t.Errorf("status = %q, want %q", m.Status, StatusClean)
			}
		})
	}
}
