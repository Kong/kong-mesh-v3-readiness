package preflight

import "testing"

// TestMeshAccessLogOtelEndpoint checks the deprecated OpenTelemetry `endpoint`
// is found in every MeshAccessLog section that carries backends, including the
// inbound `rules[]` form that replaces `from`.
func TestMeshAccessLogOtelEndpoint(t *testing.T) {
	const title = "MeshAccessLog uses OpenTelemetry `endpoint`"
	otel := func(endpoint string) map[string]any {
		return map[string]any{"default": map[string]any{"backends": []any{
			map[string]any{"type": "OpenTelemetry", "openTelemetry": map[string]any{"endpoint": endpoint}},
		}}}
	}
	for _, tc := range []struct {
		name     string
		section  string
		endpoint string
		want     bool
	}{
		{"to", "to", "otel:4317", true},
		{"from", "from", "otel:4317", true},
		{"rules", "rules", "otel:4317", true},
		{"rules without endpoint", "rules", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/meshaccesslogs": listBody(t, map[string]any{
					"type": "MeshAccessLog", "mesh": "default", "name": "mal",
					"spec": map[string]any{
						"targetRef": map[string]any{"kind": "Mesh"},
						tc.section:  []any{otel(tc.endpoint)},
					},
				}),
			})
			if _, got := findFinding(m, "blocker", "OpenTelemetry endpoint", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}
