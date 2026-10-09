package preflight

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMeshRetryLegacyRetryFields covers the legacy Retry conf fields MeshRetry
// never defined: 2.x drops them silently, 3.0 rejects the write, so a stored
// spec carrying one cannot be re-applied after the upgrade.
func TestMeshRetryLegacyRetryFields(t *testing.T) {
	const title = "MeshRetry uses legacy Retry fields"
	retry := func(defaults string) map[string]any {
		return map[string]any{
			"type": "MeshRetry", "mesh": "default", "name": "mr",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{
					map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "default": jsonMap(t, defaults)},
				},
			},
		}
	}
	for _, tc := range []struct {
		name, defaults string
		want           bool
	}{
		{"retriableStatusCodes", `{"http":{"retriableStatusCodes":[500]}}`, true},
		{"retriableMethods", `{"http":{"retriableMethods":["GET"]}}`, true},
		{"maxConnectAttempts", `{"tcp":{"maxConnectAttempts":5}}`, true},
		{"all three", `{"http":{"retriableStatusCodes":[500],"retriableMethods":["GET"]},"tcp":{"maxConnectAttempts":5}}`, true},
		{"empty tcp", `{"tcp":{}}`, false},
		{"valid tcp field", `{"tcp":{"maxConnectAttempt":5}}`, false},
		{"valid http conf", `{"http":{"numRetries":3,"retryOn":["5xx","503"]}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/meshretries": listBody(t, retry(tc.defaults)),
			})
			if _, got := findFinding(m, "blocker", "MeshRetry", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestMeshRetryInvalidRetryOn covers the retryOn condition list, which write
// validation checks case-sensitively on 2.14 and 3.0 alike: the CamelCase named
// conditions plus, for HTTP only, any numeric HTTP status code.
func TestMeshRetryInvalidRetryOn(t *testing.T) {
	const title = "MeshRetry retryOn names an unknown condition"
	retry := func(defaults string) map[string]any {
		return map[string]any{
			"type": "MeshRetry", "mesh": "default", "name": "mr",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{
					map[string]any{"targetRef": map[string]any{"kind": "Mesh"}, "default": jsonMap(t, defaults)},
				},
			},
		}
	}
	for _, tc := range []struct {
		name, defaults string
		want           bool
	}{
		{"envoy reset", `{"http":{"retryOn":["5xx","reset"]}}`, true},
		{"envoy connect-failure", `{"http":{"retryOn":["connect-failure"]}}`, true},
		{"uppercase 5XX", `{"http":{"retryOn":["5XX"]}}`, true},
		{"grpc kebab-case", `{"grpc":{"retryOn":["deadline-exceeded"]}}`, true},
		{"grpc unknown", `{"grpc":{"retryOn":["Wrong"]}}`, true},
		{"valid http named", `{"http":{"retryOn":["5xx","GatewayError","ConnectFailure"]}}`, false},
		{"valid numeric", `{"http":{"retryOn":["429","503"]}}`, false},
		{"invalid numeric", `{"http":{"retryOn":["952"]}}`, true},
		{"numeric on grpc", `{"grpc":{"retryOn":["13"]}}`, true},
		{"valid grpc named", `{"grpc":{"retryOn":["Canceled","DeadlineExceeded"]}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/meshretries": listBody(t, retry(tc.defaults)),
			})
			if _, got := findFinding(m, "blocker", "MeshRetry", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestMeshRetryFindingsMerge verifies both MeshRetry findings fire once per
// resource however many `to` items carry the offending fields, alongside each
// other and alongside a clean second resource.
func TestMeshRetryFindingsMerge(t *testing.T) {
	items := []map[string]any{
		{
			"type": "MeshRetry", "mesh": "default", "name": "mr-bad",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{
					map[string]any{
						"targetRef": map[string]any{"kind": "Mesh"},
						"default":   jsonMap(t, `{"http":{"retriableMethods":["GET"],"retryOn":["reset"]}}`),
					},
					map[string]any{
						"targetRef": map[string]any{"kind": "Mesh"},
						"default":   jsonMap(t, `{"tcp":{"maxConnectAttempts":5},"grpc":{"retryOn":["internal"]}}`),
					},
				},
			},
		},
		{
			"type": "MeshRetry", "mesh": "default", "name": "mr-good",
			"spec": map[string]any{
				"targetRef": map[string]any{"kind": "Mesh"},
				"to": []any{
					map[string]any{
						"targetRef": map[string]any{"kind": "Mesh"},
						"default":   jsonMap(t, `{"http":{"numRetries":3,"retryOn":["5xx"]}}`),
					},
				},
			},
		},
	}
	m := auditResponses(t, map[string]string{"/meshretries": listBody(t, items...)})
	for _, title := range []string{"MeshRetry uses legacy Retry fields", "MeshRetry retryOn names an unknown condition"} {
		f, ok := findFinding(m, "blocker", "MeshRetry", title)
		if !ok {
			t.Errorf("finding %q missing\nfindings: %+v", title, m.Findings)
			continue
		}
		if f.Count != 1 {
			t.Errorf("finding %q count = %d, want 1\nexamples: %v", title, f.Count, f.Examples)
		}
		if len(f.Examples) != 1 || !strings.Contains(f.Examples[0], "mr-bad") {
			t.Errorf("finding %q examples = %v, want only the offending resource", title, f.Examples)
		}
	}
}

// TestMeshRetryManualCheckListed: the manifest-side half of the issue cannot be
// seen through the control-plane API, so it ships as a manual check.
func TestMeshRetryManualCheckListed(t *testing.T) {
	m := auditResponses(t, nil)
	const title = "Fix MeshRetry manifests carrying legacy Retry fields"
	for _, c := range m.Manual {
		if c.Title == title {
			return
		}
	}
	t.Errorf("manual check %q missing\nmanual: %+v", title, m.Manual)
}

// jsonMap decodes a JSON object literal into a map, for specs whose shape a
// map[string]any literal would spell awkwardly.
func jsonMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("unmarshal %s: %v", s, err)
	}
	return m
}
