package preflight

import (
	"encoding/json"
	"testing"
)

func TestMeshMetricTLSMigration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   string
		config string
		block  bool
	}{
		{"active backend", "MeshMetric", `{"type":"Prometheus","prometheus":{"tls":{"mode":"ActiveMTLSBackend"}}}`, true},
		{"second backend", "MeshMetric", `{"type":"OpenTelemetry"},{"type":"Prometheus","prometheus":{"tls":{"mode":"ActiveMTLSBackend"}}}`, true},
		{"provided server TLS", "MeshMetric", `{"type":"Prometheus","prometheus":{"tls":{"mode":"ProvidedTLS"}}}`, false},
		{"disabled TLS", "MeshMetric", `{"type":"Prometheus","prometheus":{"tls":{"mode":"Disabled"}}}`, false},
		{"no TLS", "MeshMetric", `{"type":"Prometheus","prometheus":{}}`, false},
		{"empty backend", "MeshMetric", `{"type":"Prometheus"}`, false},
		{"other backend", "MeshMetric", `{"type":"OpenTelemetry","prometheus":{"tls":{"mode":"ActiveMTLSBackend"}}}`, false},
		{"trace policy", "MeshTrace", `{"type":"Prometheus","prometheus":{"tls":{"mode":"ActiveMTLSBackend"}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := auditor{rep: &collector{}}
			it := resourceItem{Type: tc.kind, Spec: json.RawMessage(`{"default":{"backends":[` + tc.config + `]}}`)}
			a.checkPolicyFields(it, "test-metric")
			found := false
			for _, finding := range a.rep.findings {
				if finding.title == "MeshMetric ActiveMTLSBackend does not enable TLS" {
					found = true
					if finding.severity != blocker {
						t.Fatalf("TLS migration finding has severity %q", finding.severity)
					}
				}
			}
			if found != tc.block {
				t.Fatalf("TLS migration blocker = %v, want %v", found, tc.block)
			}
		})
	}
}

func TestMeshMetricMalformedTLSIsInconclusive(t *testing.T) {
	a := auditor{rep: &collector{}}
	it := resourceItem{Type: "MeshMetric", Spec: json.RawMessage(`{"default":{"backends":[{"type":"Prometheus","prometheus":{"tls":{"mode":true}}}]}}`)}
	a.checkPolicyFields(it, "test-metric")
	if a.rep.parseErrors != 1 || !a.rep.incomplete() {
		t.Fatal("a malformed TLS mode must make the audit incomplete")
	}
}
