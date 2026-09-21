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

// overview builds one DataplaneOverview item for /dataplanes+insights, the shape
// checkOutboundDefaults reads: the Dataplane spec nested under "dataplane", the
// insight (with kuma-dp's reported metadata) next to it.
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

// tproxySpec is the legacy (pre-3.0) way a Dataplane declares transparent
// proxying: the redirect ports on its spec.
func tproxySpec(extra map[string]any) map[string]any {
	tp := map[string]any{"redirectPortInbound": 15006, "redirectPortOutbound": 15001}
	maps.Copy(tp, extra)
	return map[string]any{"transparentProxying": tp}
}

// auditOverviews audits a mock control plane whose /dataplanes+insights serves
// the given overviews and whose every other collection is empty.
func auditOverviews(t *testing.T, items ...map[string]any) Report {
	t.Helper()
	return auditResponses(t, map[string]string{"/dataplanes+insights": listBody(t, items...)})
}

var (
	universalLabels  = map[string]any{"kuma.io/env": "universal"}
	kubernetesLabels = map[string]any{"kuma.io/env": "kubernetes"}
)

// TestOutboundDenyFlagsProxiesWithNoReachableBackends covers the 3.0 flip that
// stops treating an unset reachableBackends as "every destination in the mesh":
// a transparent-proxy proxy that selects nothing loses every outbound, and the
// remediation differs per environment, so the two are reported separately.
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

// TestOutboundDenySkipsProxiesThatKeepOutbounds guards the check against the
// noise it would otherwise generate: every proxy that still resolves outbounds
// on 3.0, and every proxy the flip cannot reach at all, must stay unflagged.
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

// TestOutboundDenyReportsSummaryNotPerProxy checks the summary form the finding
// exists to produce: many affected proxies collapse into one bullet whose detail
// carries the N-of-M tally, with the unaffected ones counted in M only.
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

// TestOutboundDenyNotConcludedFromCoverageGap guards the "never fake a clean
// report" rule in reverse: an unreadable /dataplanes+insights must not be read
// as "no proxy configures reachableBackends".
func TestOutboundDenyNotConcludedFromCoverageGap(t *testing.T) {
	m := auditWithNotFound(t, nil, "/dataplanes+insights")
	for _, title := range []string{titleUniversalDeny, titleKubernetesDeny} {
		if _, ok := findFinding(m, "blocker", categoryOutboundDefaults, title); ok {
			t.Errorf("finding %q concluded from an unread collection\nfindings: %+v", title, m.Findings)
		}
	}
	if m.Status != StatusInconclusive {
		t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
	}
}

// meshItem builds one "default" Mesh list item, optionally carrying the
// mesh-level outbound passthrough switch.
func meshItem(passthrough *bool) map[string]any {
	it := map[string]any{"type": "Mesh", "name": "default", "meshServices": map[string]any{"mode": "Exclusive"}}
	if passthrough != nil {
		it["networking"] = map[string]any{"outbound": map[string]any{"passthrough": *passthrough}}
	}
	return it
}

// TestPassthroughDefaultFlagsMeshWithNoPolicy covers the second 3.0 flip: a
// transparent-proxy proxy matched by no MeshPassthrough stops getting a
// passthrough cluster, so a mesh with no such policy loses external egress.
func TestPassthroughDefaultFlagsMeshWithNoPolicy(t *testing.T) {
	m := auditResponses(t, map[string]string{
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

// TestPassthroughDefaultSkipsUnaffectedMeshes checks the three preconditions that
// keep the finding off meshes the flip cannot affect.
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
				"/meshes":              listBody(t, meshItem(&passthroughOff)),
				"/dataplanes+insights": listBody(t, overview("dp-1", universalLabels, tproxySpec(nil), nil)),
			},
		},
		{
			name:      "mesh has no transparent-proxy proxies",
			responses: map[string]string{"/meshes": listBody(t, meshItem(nil))},
		},
		{
			name:      "MeshPassthrough collection could not be read",
			responses: map[string]string{"/meshes": listBody(t, meshItem(nil))},
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
