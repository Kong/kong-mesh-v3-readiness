package preflight

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Schema/tool identifiers stamped into every JSON report so a consumer (or
// ParseReport) can recognize and version the payload.
const (
	// SchemaVersion is the JSON schema value stamped into every report.
	SchemaVersion = "kuma3-preflight/v3"
	// ToolName identifies this tool in the JSON payload and in the User-Agent
	// header of outbound HTTP requests.
	ToolName = "kuma3-preflight"
)

// Audit outcome, mirrored by the process exit code the CLI derives from it.
const (
	StatusClean        = "clean"
	StatusBlockers     = "blockers"
	StatusInconclusive = "inconclusive"
	StatusFailed       = "failed"
)

// Severity strings as they appear in Finding.Severity. SeverityBlocker gates CI;
// SeverityInfo is advisory only. The "warning" tier still exists internally for
// backward-compatible --from-json parsing, but no check emits one.
const (
	SeverityBlocker = "blocker"
	SeverityInfo    = "info"
)

// Report is the canonical, serializable form of a CP-audit report. Both output
// formats (JSON via RenderJSON, HTML via RenderHTML) are rendered from this single
// structure, and ParseReport loads it back, so they can never drift apart.
// (Markdown is produced only by the CLI's --classify mode, from a different model.)
type Report struct {
	// Schema is "kuma3-preflight/vN"; ParseReport accepts any prior vN by prefix.
	Schema      string `json:"schema" jsonschema:"pattern=^kuma3-preflight/v[0-9]+$"`
	Tool        string `json:"tool" jsonschema:"enum=kuma3-preflight"`
	GeneratedAt string `json:"generatedAt,omitempty" jsonschema:"format=date-time"`
	// Status reflects report trustworthiness first: an incomplete audit is
	// inconclusive even when it still found blockers elsewhere.
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

// Summary tallies findings by severity plus coverage/parse-error counts.
type Summary struct {
	Blockers int `json:"blockers" jsonschema:"minimum=0"`
	// Warnings stays for ParseReport backward compatibility; no check emits one.
	Warnings       int `json:"warnings" jsonschema:"minimum=0"`
	Info           int `json:"info" jsonschema:"minimum=0"`
	CoverageGaps   int `json:"coverageGaps" jsonschema:"minimum=0"`
	ParseErrors    int `json:"parseErrors" jsonschema:"minimum=0"`
	SystemFindings int `json:"systemFindings" jsonschema:"minimum=0"`
}

// Finding is one (severity, category, title) grouped occurrence in the report.
type Finding struct {
	// Severity "warning" only appears in pre-re-grade payloads; no current check emits one.
	Severity string `json:"severity" jsonschema:"enum=blocker,enum=warning,enum=info"`
	Group    string `json:"group" jsonschema:"enum=Control plane,enum=Mesh object,enum=Policies,enum=Removed resources,enum=Data plane & workloads,enum=Other"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	// Doc links to the Kong Mesh page explaining the 3.0 replacement API/feature.
	// Optional: omitted for findings with no replacement to point at.
	Doc      string   `json:"doc,omitempty" jsonschema:"format=uri"`
	Count    int      `json:"count" jsonschema:"minimum=1"`
	Examples []string `json:"examples" jsonschema:"maxItems=10"`
}

// CoverageGap records a collection that could not be audited — a 404 or a
// transport error — so the report distinguishes "absent" from "not observed".
type CoverageGap struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ManualCheck is one upgrade item the CP API cannot surface, rendered as a card in
// the manual checklist. Title is always set; Detail and Command enrich a card with
// an explanation and a copy-paste validation command when one exists.
type ManualCheck struct {
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	Command string `json:"command,omitempty"`
}

// UnmarshalJSON accepts either the v3 object form or the v2 form, where each
// manual check was a bare string. A legacy string maps to Title, so ParseReport
// still renders reports captured before the schema bump (the v2 schema value
// passes ParseReport's prefix check).
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

// Finding groups organize the rendered report into top-level sections. Every
// category maps to exactly one group; an unmapped category falls into groupOther
// so a newly added check is never silently dropped from the report.
const (
	groupControlPlane     = "Control plane"
	groupMeshObject       = "Mesh object"
	groupPolicies         = "Policies"
	groupRemovedResources = "Removed resources"
	groupDataPlane        = "Data plane & workloads"
	groupOther            = "Other"
)

// groupOrder is the display order of the groups, top to bottom.
var groupOrder = []string{
	groupControlPlane,
	groupMeshObject,
	groupPolicies,
	groupRemovedResources,
	groupDataPlane,
	groupOther,
}

var categoryToGroup = map[string]string{
	cpConfigCategory:           groupControlPlane,
	cpVersionCategory:          groupControlPlane,
	"Mesh object settings":     groupMeshObject,
	"MeshService mode":         groupMeshObject,
	"Policy `from` field":      groupPolicies,
	"Top-level targetRef kind": groupPolicies,
	"`to` targetRef kind":      groupPolicies,
	"targetRef proxyTypes":     groupPolicies,
	"Relocated policy fields":  groupPolicies,
	"OpenTelemetry endpoint":   groupPolicies,
	"Removed policies":         groupPolicies,
	"Removed resources":        groupRemovedResources,
	"reachableServices":        groupDataPlane,
	"Workload grouping":        groupDataPlane,
	"Gateway in Dataplane":     groupDataPlane,
	"Dataplane probes":         groupDataPlane,
	"Dataplane metrics":        groupDataPlane,
	"Dataplane version":        groupDataPlane,
	"Dataplane features":       groupDataPlane,
	"Dataplane DNS":            groupDataPlane,
	"Non-RFC-1035 names":       groupOther,
	"Unparseable resources":    groupOther,
	"Zone proxies":             groupOther,
}

// categoryGroup returns the display group for a finding category.
func categoryGroup(category string) string {
	if g, ok := categoryToGroup[category]; ok {
		return g
	}
	return groupOther
}

// groupIndex gives a group its position in groupOrder (unknown groups sort last)
// so findings can be ordered group-by-group deterministically.
func groupIndex(group string) int {
	for i, g := range groupOrder {
		if g == group {
			return i
		}
	}
	return len(groupOrder)
}

// severityRank orders severities for rendering: blocker, then warning, then info,
// unknown last.
func severityRank(sev string) int {
	switch sev {
	case blocker.String():
		return 0
	case warning.String():
		return 1
	case info.String():
		return 2
	default:
		return 3
	}
}

// normalizeModel makes a model canonical for rendering: every finding gets its
// group, and findings are sorted (severity, group order, category, title) so each
// group is contiguous. Renderers rely on that contiguity, so both fresh audits and
// ParseReport (including older payloads written before the group field existed)
// render identically — preserving the one-model/three-renderers contract.
func normalizeModel(m *Report) {
	for i := range m.Findings {
		if m.Findings[i].Group == "" {
			m.Findings[i].Group = categoryGroup(m.Findings[i].Category)
		}
	}
	sort.SliceStable(m.Findings, func(i, j int) bool {
		a, b := m.Findings[i], m.Findings[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if gi, gj := groupIndex(a.Group), groupIndex(b.Group); gi != gj {
			return gi < gj
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Title < b.Title
	})
}

func (s severity) String() string {
	switch s {
	case blocker:
		return "blocker"
	case warning:
		return "warning"
	case info:
		return "info"
	default:
		return "unknown"
	}
}

// status classifies the run; incompleteness outranks blockers because a partial
// report is not fully trustworthy even when it retained real findings. Warnings
// are advisory and do not gate: a run with only warnings (no blockers, fully
// observed) is still clean.
func (r *collector) status() string {
	switch {
	case r.incomplete():
		return StatusInconclusive
	case r.count(blocker) > 0:
		return StatusBlockers
	default:
		return StatusClean
	}
}

// toModel projects an audited report onto the serializable model. Findings and
// coverage gaps are sorted deterministically (by severity, category, title /
// by path) so JSON output is stable across runs.
func (r *collector) toModel(generatedAt string) Report {
	product := r.cp.Product
	if product == "" {
		product = "Kuma"
	}
	m := Report{
		Schema:       SchemaVersion,
		Tool:         ToolName,
		GeneratedAt:  generatedAt,
		Status:       r.status(),
		ControlPlane: ControlPlane{Product: product, Version: r.cp.Version, Mode: r.cp.Mode},
		Meshes:       append([]string{}, r.meshes...),
		Summary: Summary{
			Blockers:       r.count(blocker),
			Warnings:       r.count(warning),
			Info:           r.count(info),
			CoverageGaps:   len(r.coverage),
			ParseErrors:    r.parseErrors,
			SystemFindings: r.systemFindings,
		},
		Findings: []Finding{},
		Coverage: []CoverageGap{},
		Manual:   append([]ManualCheck{}, r.manual...),
	}

	for _, f := range r.findings {
		m.Findings = append(m.Findings, Finding{
			Severity: f.severity.String(),
			Group:    categoryGroup(f.category),
			Category: f.category,
			Title:    f.title,
			Detail:   f.detail,
			Doc:      f.doc,
			Count:    f.count,
			Examples: append([]string{}, f.examples...),
		})
	}
	normalizeModel(&m)

	cg := append([]coverageGap(nil), r.coverage...)
	sort.SliceStable(cg, func(i, j int) bool { return cg[i].path < cg[j].path })
	for _, g := range cg {
		m.Coverage = append(m.Coverage, CoverageGap{Path: g.path, Reason: g.reason})
	}
	return m
}

// FailureReport builds the model emitted when the audit itself could not run, so
// JSON/HTML consumers receive a structured "do not trust this" payload.
func FailureReport(addr string, auditErr error, generatedAt string) Report {
	return Report{
		Schema:      SchemaVersion,
		Tool:        ToolName,
		GeneratedAt: generatedAt,
		Status:      StatusFailed,
		Address:     addr,
		Error:       auditErr.Error(),
		Meshes:      []string{},
		Findings:    []Finding{},
		Coverage:    []CoverageGap{},
		Manual:      []ManualCheck{},
	}
}

// RenderJSON renders the report as 2-space-indented JSON with a trailing newline.
func (m Report) RenderJSON() (string, error) {
	return marshalIndentJSON(m)
}

// marshalIndentJSON renders v as 2-space-indented JSON with a trailing newline —
// the on-disk/stdout shape shared by the CP-audit renderer.
func marshalIndentJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// RenderHTML embeds the report JSON into a self-contained, dependency-free page
// (see html.go) that renders it client-side. json.Marshal escapes <, >, & to
// \u00xx, so the payload is safe inside the <script> tag.
func (m Report) RenderHTML() (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return htmlHead + string(b) + htmlTail, nil
}

// ParseReport decodes and validates a JSON report payload (as produced by
// RenderJSON / captured via --from-json), normalizing it so every renderer sees
// group-contiguous findings regardless of when the payload was captured.
func ParseReport(data []byte) (Report, error) {
	var m Report
	if err := json.Unmarshal(data, &m); err != nil {
		return Report{}, fmt.Errorf("parsing JSON report: %w", err)
	}
	// Validate the schema value, not merely its presence: a non-empty but foreign
	// `schema` (e.g. an unrelated JSON document, or a classification report fed where a
	// report is expected) must be rejected, not silently mis-decoded.
	if !strings.HasPrefix(m.Schema, ToolName+"/") {
		return Report{}, fmt.Errorf("does not look like a %s JSON report (schema %q)", ToolName, m.Schema)
	}
	normalizeModel(&m)
	return m, nil
}
