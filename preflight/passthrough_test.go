package preflight

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

const passthroughTitle = "Transparent-proxy Dataplane not selected by any MeshPassthrough"

const selectedPath = "/meshes/default/meshpassthroughs/allow-ext/_resources/dataplanes"

// passthroughEstate is a mesh with two transparent proxies and one without, plus
// a MeshPassthrough the control plane reports as selecting only dp-selected.
func passthroughEstate(t *testing.T, mesh, policy map[string]any) map[string]string {
	t.Helper()
	dp := func(name string, networking map[string]any) map[string]any {
		return map[string]any{
			"type": "Dataplane", "mesh": "default", "name": name,
			"labels":     map[string]any{"kuma.io/env": "kubernetes"},
			"networking": networking,
		}
	}
	tp := map[string]any{"transparentProxying": map[string]any{"redirectPortOutbound": 15001, "reachableBackends": map[string]any{}}}
	mesh["type"], mesh["name"] = "Mesh", "default"
	mesh["meshServices"] = map[string]any{"mode": "Exclusive"}
	policy["type"], policy["mesh"], policy["name"] = "MeshPassthrough", "default", "allow-ext"
	policy["spec"] = map[string]any{"targetRef": map[string]any{"kind": "Dataplane", "labels": map[string]any{"app": "a"}}, "default": map[string]any{"passthroughMode": "All"}}
	return map[string]string{
		"/meshes": listBody(t, mesh),
		"/dataplanes": listBody(t,
			dp("dp-selected", tp),
			dp("dp-unselected", tp),
			dp("dp-no-tp", map[string]any{"inbound": []any{map[string]any{"port": 8080}}}),
		),
		"/meshpassthroughs": listBody(t, policy),
		selectedPath:        listBody(t, map[string]any{"type": "Dataplane", "mesh": "default", "name": "dp-selected"}),
	}
}

func passthroughExamples(m Report) []string {
	f, ok := findFinding(m, "blocker", "Dataplane networking", passthroughTitle)
	if !ok {
		return nil
	}
	return f.Examples
}

// TestPassthroughDefault covers the 3.0 MeshPassthrough default (None when no
// policy selects a transparent proxy): only an unselected transparent proxy in a
// mesh whose passthrough is still on loses passthrough.
func TestPassthroughDefault(t *testing.T) {
	cases := []struct {
		name   string
		mesh   map[string]any
		policy map[string]any
		want   []string
	}{
		{
			name: "unselected transparent proxy is flagged",
			mesh: map[string]any{}, policy: map[string]any{},
			want: []string{"default/dp-unselected"},
		},
		{
			name:   "mesh with passthrough already off is unaffected",
			mesh:   map[string]any{"networking": map[string]any{"outbound": map[string]any{"passthrough": false}}},
			policy: map[string]any{},
		},
		{
			name: "explicit passthrough on still changes",
			mesh: map[string]any{"networking": map[string]any{"outbound": map[string]any{"passthrough": true}}}, policy: map[string]any{},
			want: []string{"default/dp-unselected"},
		},
		{
			name: "shadow policy does not select",
			mesh: map[string]any{}, policy: map[string]any{"labels": map[string]any{"kuma.io/effect": "shadow"}},
			want: []string{"default/dp-selected", "default/dp-unselected"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, passthroughEstate(t, tc.mesh, tc.policy))
			got := passthroughExamples(m)
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestPassthroughDefaultUnreadableSelection confirms an unreadable selection is a
// coverage gap for that mesh, not a guess that nothing is selected.
func TestPassthroughDefaultUnreadableSelection(t *testing.T) {
	t.Run("selection endpoint 404", func(t *testing.T) {
		responses := passthroughEstate(t, map[string]any{}, map[string]any{})
		delete(responses, selectedPath)
		m := auditWithNotFound(t, responses, selectedPath)
		if got := passthroughExamples(m); got != nil {
			t.Errorf("flagged %v despite unreadable selection", got)
		}
		if m.Status != StatusInconclusive {
			t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
		}
	})
	t.Run("MeshPassthrough list unreadable", func(t *testing.T) {
		responses := passthroughEstate(t, map[string]any{}, map[string]any{})
		m := auditResponsesFunc(t, func(path string) (string, int, bool) {
			if path == "/meshpassthroughs" {
				return `{}`, http.StatusInternalServerError, true
			}
			body, ok := responses[path]
			return body, http.StatusOK, ok
		})
		if got := passthroughExamples(m); got != nil {
			t.Errorf("flagged %v despite unreadable MeshPassthrough list", got)
		}
		if m.Status != StatusInconclusive {
			t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
		}
	})
}

// TestPassthroughDefaultAlreadyRestricted confirms a CP already on
// `defaults.restrictOutbound: true` is not flagged: 2.14 then already denies
// passthrough to an unselected proxy, so the upgrade changes nothing for it.
func TestPassthroughDefaultAlreadyRestricted(t *testing.T) {
	responses := passthroughEstate(t, map[string]any{}, map[string]any{})
	responses["/config"] = strings.Replace(readyConfigJSON, `"mode": "zone",`, `"mode": "zone", "defaults": {"restrictOutbound": true},`, 1)
	m := auditResponses(t, responses)
	if got := passthroughExamples(m); got != nil {
		t.Errorf("flagged %v although the CP already restricts outbound", got)
	}
}
