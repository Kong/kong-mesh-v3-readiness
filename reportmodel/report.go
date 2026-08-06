// Package reportmodel defines the JSON contracts kuma3-preflight emits: Report
// (the CP-audit report) and Classification (the --classify output). Both are
// stable, versioned shapes — --from-json reloads Report verbatim, and every
// renderer (JSON/HTML/Markdown) draws from the same struct. docs/openapi.yaml
// is generated from these types by tools/openapigen; run `go generate ./...`
// after changing them.
package reportmodel

import (
	"bytes"
	"encoding/json"
)

// Report is the canonical, serializable form of a CP-audit report.
type Report struct {
	// Schema is "kuma3-preflight/vN"; --from-json accepts any prior vN by prefix.
	Schema      string `json:"schema" jsonschema:"pattern=^kuma3-preflight/v[0-9]+$"`
	Tool        string `json:"tool" jsonschema:"enum=kuma3-preflight"`
	GeneratedAt string `json:"generatedAt,omitempty" jsonschema:"format=date-time"`
	// Status: blockers outranks inconclusive, so a coverage gap never softens a failing audit.
	Status  string `json:"status" jsonschema:"enum=clean,enum=blockers,enum=inconclusive,enum=failed"`
	Address string `json:"address,omitempty"`
	// Error never echoes a raw HTTP response body or bearer token.
	Error        string       `json:"error,omitempty"`
	ControlPlane ControlPlane `json:"controlPlane"`
	Meshes       []string     `json:"meshes"`
	Summary      Summary      `json:"summary"`
	Findings     []Finding    `json:"findings"`
	// Coverage gaps make the run inconclusive, never clean.
	Coverage []CoverageGap `json:"coverageGaps"`
	Manual   []ManualCheck `json:"manualChecks"`
}

// ControlPlane identifies the audited control plane.
type ControlPlane struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Mode    string `json:"mode,omitempty" jsonschema:"enum=,enum=standalone,enum=zone,enum=global"`
}

// Summary is the finding-count rollup shown at the top of a report.
type Summary struct {
	Blockers int `json:"blockers" jsonschema:"minimum=0"`
	// Warnings stays for --from-json backward compatibility; no check emits one.
	Warnings       int `json:"warnings" jsonschema:"minimum=0"`
	Info           int `json:"info" jsonschema:"minimum=0"`
	CoverageGaps   int `json:"coverageGaps" jsonschema:"minimum=0"`
	ParseErrors    int `json:"parseErrors" jsonschema:"minimum=0"`
	SystemFindings int `json:"systemFindings" jsonschema:"minimum=0"`
}

// Finding is one deprecation/blocker/advisory item, merged by (Severity, Category, Title).
type Finding struct {
	// Severity "warning" only appears in pre-re-grade payloads; no current check emits one.
	Severity string   `json:"severity" jsonschema:"enum=blocker,enum=warning,enum=info"`
	Group    string   `json:"group" jsonschema:"enum=Control plane,enum=Mesh object,enum=Policies,enum=Removed resources,enum=Data plane & workloads,enum=Other"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Doc      string   `json:"doc,omitempty" jsonschema:"format=uri"`
	Count    int      `json:"count" jsonschema:"minimum=1"`
	Examples []string `json:"examples" jsonschema:"maxItems=10"`
}

// CoverageGap is a collection that could not be audited — for example a 404 on a resource list.
type CoverageGap struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ManualCheck is one upgrade item the CP API cannot surface.
type ManualCheck struct {
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	Command string `json:"command,omitempty"`
}

// UnmarshalJSON accepts the v3 object form or the v2 bare-string form, mapping
// a legacy string to Title so --from-json still renders older reports.
func (m *ManualCheck) UnmarshalJSON(b []byte) error {
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '"' {
		var title string
		if err := json.Unmarshal(b, &title); err != nil {
			return err
		}
		m.Title = title
		return nil
	}
	type alias ManualCheck // avoid recursing into this method
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*m = ManualCheck(a)
	return nil
}
