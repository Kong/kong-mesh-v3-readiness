package preflight

import "testing"

// TestInboundProtocol covers the 3.0 inbound protocol rules: the kuma.io/protocol
// tag no longer sets the protocol, and Kafka is no longer accepted.
func TestInboundProtocol(t *testing.T) {
	const (
		tagOnly     = "Dataplane inbound sets its protocol only through kuma.io/protocol"
		unsupported = "Dataplane inbound uses a protocol 3.0 rejects"
	)
	for _, tc := range []struct {
		name    string
		env     string
		inbound map[string]any
		want    []string
	}{
		{"universal tag without field", "universal", map[string]any{"port": 80, "tags": map[string]any{"kuma.io/protocol": "http"}}, []string{tagOnly}},
		{"universal tag with field", "universal", map[string]any{"port": 80, "protocol": "http", "tags": map[string]any{"kuma.io/protocol": "http"}}, nil},
		{"universal kafka field", "universal", map[string]any{"port": 9092, "protocol": "kafka"}, []string{unsupported}},
		{"kubernetes kafka field", "kubernetes", map[string]any{"port": 9092, "protocol": "kafka"}, []string{unsupported}},
		{"universal mysql field", "universal", map[string]any{"port": 3306, "protocol": "MySQL"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditDataplane(t, map[string]any{
				"labels":     map[string]any{"kuma.io/env": tc.env, "kuma.io/workload": "w"},
				"networking": map[string]any{"inbound": []any{tc.inbound}},
			})
			for _, title := range []string{tagOnly, unsupported} {
				_, got := findFinding(m, "blocker", "Dataplane networking", title)
				want := len(tc.want) > 0 && tc.want[0] == title
				if got != want {
					t.Errorf("%q flagged = %v, want %v\nfindings: %+v", title, got, want, m.Findings)
				}
			}
		})
	}
}

// TestReadinessUnixSocket flags a proxy still advertising Unix-socket readiness,
// which a 3.0 control plane no longer serves.
func TestReadinessUnixSocket(t *testing.T) {
	const title = "Dataplane reports readiness over a Unix socket"
	insight := func(features ...any) map[string]any {
		return map[string]any{
			"type": "DataplaneOverview", "mesh": "default", "name": "dp-1",
			"dataplaneInsight": map[string]any{
				"subscriptions": []any{map[string]any{"version": map[string]any{"kumaDp": map[string]any{"version": "2.13.4"}}}},
				"metadata":      map[string]any{"features": features},
			},
		}
	}
	for _, tc := range []struct {
		name     string
		features []any
		want     bool
	}{
		{"advertises unix socket readiness", []any{featureUnifiedNaming, featureReadinessUnixSocket}, true},
		{"TCP readiness", []any{featureUnifiedNaming}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/dataplanes+insights": listBody(t, insight(tc.features...))})
			if _, got := findFinding(m, "blocker", "Dataplane features", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}
