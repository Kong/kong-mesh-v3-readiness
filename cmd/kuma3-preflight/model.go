package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Schema/tool identifiers stamped into every JSON report so a consumer (or the
// --from-json renderer) can recognize and version the payload.
const (
	reportSchema = "kuma3-preflight/v1"
	toolName     = "kuma3-preflight"
)

// Audit outcome, mirrored by the process exit code (see exitForStatus).
const (
	statusClean        = "clean"
	statusBlockers     = "blockers"
	statusInconclusive = "inconclusive"
	statusFailed       = "failed"
)

// reportModel is the canonical, serializable form of a report. Every output
// format (markdown, json, html) is rendered from this single structure, and
// --from-json loads it back, so the three formats can never drift apart.
type reportModel struct {
	Schema       string          `json:"schema"`
	Tool         string          `json:"tool"`
	GeneratedAt  string          `json:"generatedAt,omitempty"`
	Status       string          `json:"status"`
	Address      string          `json:"address,omitempty"`
	Error        string          `json:"error,omitempty"`
	ControlPlane controlPlane    `json:"controlPlane"`
	Meshes       []string        `json:"meshes"`
	Summary      summary         `json:"summary"`
	Findings     []findingModel  `json:"findings"`
	Coverage     []coverageModel `json:"coverageGaps"`
	Manual       []string        `json:"manualChecks"`
}

type controlPlane struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Mode    string `json:"mode,omitempty"`
}

type summary struct {
	Blockers       int `json:"blockers"`
	Warnings       int `json:"warnings"`
	Info           int `json:"info"`
	CoverageGaps   int `json:"coverageGaps"`
	ParseErrors    int `json:"parseErrors"`
	SystemFindings int `json:"systemFindings"`
}

type findingModel struct {
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Count    int      `json:"count"`
	Examples []string `json:"examples"`
}

type coverageModel struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
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

// status classifies the run; blockers take precedence over inconclusive so a
// failing audit is never softened by a coverage gap.
func (r *report) status() string {
	switch {
	case r.count(blocker) > 0:
		return statusBlockers
	case r.incomplete():
		return statusInconclusive
	default:
		return statusClean
	}
}

// toModel projects an audited report onto the serializable model. Findings and
// coverage gaps are sorted deterministically (by severity, category, title /
// by path) so JSON output is stable across runs.
func (r *report) toModel(generatedAt string) reportModel {
	product := r.cp.Product
	if product == "" {
		product = "Kuma"
	}
	m := reportModel{
		Schema:       reportSchema,
		Tool:         toolName,
		GeneratedAt:  generatedAt,
		Status:       r.status(),
		ControlPlane: controlPlane{Product: product, Version: r.cp.Version, Mode: r.cp.Mode},
		Meshes:       append([]string{}, r.meshes...),
		Summary: summary{
			Blockers:       r.count(blocker),
			Warnings:       r.count(warning),
			Info:           r.count(info),
			CoverageGaps:   len(r.coverage),
			ParseErrors:    r.parseErrors,
			SystemFindings: r.systemFindings,
		},
		Findings: []findingModel{},
		Coverage: []coverageModel{},
		Manual:   append([]string{}, r.manual...),
	}

	fs := append([]finding(nil), r.findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].severity != fs[j].severity {
			return fs[i].severity < fs[j].severity
		}
		if fs[i].category != fs[j].category {
			return fs[i].category < fs[j].category
		}
		return fs[i].title < fs[j].title
	})
	for _, f := range fs {
		m.Findings = append(m.Findings, findingModel{
			Severity: f.severity.String(),
			Category: f.category,
			Title:    f.title,
			Detail:   f.detail,
			Count:    f.count,
			Examples: append([]string{}, f.examples...),
		})
	}

	cg := append([]coverageGap(nil), r.coverage...)
	sort.SliceStable(cg, func(i, j int) bool { return cg[i].path < cg[j].path })
	for _, g := range cg {
		m.Coverage = append(m.Coverage, coverageModel{Path: g.path, Reason: g.reason})
	}
	return m
}

// failureModel builds the model emitted when the audit itself could not run, so
// JSON/HTML consumers receive a structured "do not trust this" payload.
func failureModel(addr string, auditErr error, generatedAt string) reportModel {
	return reportModel{
		Schema:      reportSchema,
		Tool:        toolName,
		GeneratedAt: generatedAt,
		Status:      statusFailed,
		Address:     addr,
		Error:       auditErr.Error(),
		Meshes:      []string{},
		Findings:    []findingModel{},
		Coverage:    []coverageModel{},
		Manual:      []string{},
	}
}

func renderJSON(m reportModel) (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// renderHTML embeds the report JSON into a self-contained, dependency-free page
// (see html.go) that renders it client-side. json.Marshal escapes <, >, & to
// \u00xx, so the payload is safe inside the <script> tag.
func renderHTML(m reportModel) (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return htmlHead + string(b) + htmlTail, nil
}

func renderMarkdown(m reportModel) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Kuma 3.0 Upgrade Pre-flight Report")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Control plane: %s %s", m.ControlPlane.Product, m.ControlPlane.Version)
	if m.ControlPlane.Mode != "" {
		fmt.Fprintf(&b, " (mode: %s)", m.ControlPlane.Mode)
	}
	fmt.Fprintln(&b)
	meshes := "none"
	if len(m.Meshes) > 0 {
		meshes = strings.Join(m.Meshes, ", ")
	}
	fmt.Fprintf(&b, "- Meshes scanned: %s\n", meshes)
	fmt.Fprintf(&b, "- Findings: %d blockers, %d warnings, %d info\n", m.Summary.Blockers, m.Summary.Warnings, m.Summary.Info)
	if m.Summary.CoverageGaps > 0 {
		fmt.Fprintf(&b, "- Coverage gaps: %d collection(s) could not be audited\n", m.Summary.CoverageGaps)
	}
	if m.Summary.ParseErrors > 0 {
		fmt.Fprintf(&b, "- Unparseable resources: %d\n", m.Summary.ParseErrors)
	}
	if m.Summary.SystemFindings > 0 {
		fmt.Fprintf(&b, "- Includes %d CP-managed (policy-role: system) resource(s) — update these before upgrading\n", m.Summary.SystemFindings)
	}
	fmt.Fprintln(&b)

	switch m.Status {
	case statusBlockers:
		// Blocker count is already in the header; the section below lists them.
	case statusInconclusive:
		fmt.Fprintln(&b, "⚠️ No blockers found, but the audit was inconclusive (coverage gaps and/or unparseable resources) — this is NOT a clean bill of health.")
	default:
		fmt.Fprintln(&b, "✅ No blocking resources or Mesh settings found. Review the warnings and manual checks below before upgrading.")
	}
	fmt.Fprintln(&b)

	renderMarkdownSection(&b, m, "Blockers — must resolve before upgrading", "blocker")
	renderMarkdownSection(&b, m, "Warnings — should resolve", "warning")
	renderMarkdownCoverage(&b, m)
	renderMarkdownSection(&b, m, "Informational", "info")

	fmt.Fprintln(&b, "## Manual checks (not detectable via the CP API)")
	fmt.Fprintln(&b)
	for _, mc := range m.Manual {
		fmt.Fprintf(&b, "- [ ] %s\n", mc)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "_Source of truth: `docs/deprecated-features.md`._")
	return b.String()
}

// renderMarkdownSection prints one severity bucket. Findings arrive globally
// sorted by (severity, category, title), so filtering by severity preserves the
// category grouping without re-sorting.
func renderMarkdownSection(b *strings.Builder, m reportModel, heading, sev string) {
	section := make([]findingModel, 0)
	for _, f := range m.Findings {
		if f.Severity == sev {
			section = append(section, f)
		}
	}
	if len(section) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", heading)
	lastCategory := ""
	for _, f := range section {
		if f.Category != lastCategory {
			fmt.Fprintf(b, "### %s\n\n", f.Category)
			lastCategory = f.Category
		}
		fmt.Fprintf(b, "- **%s** — %d found. %s\n", f.Title, f.Count, f.Detail)
		if len(f.Examples) > 0 {
			more := ""
			if f.Count > len(f.Examples) {
				more = fmt.Sprintf(", … (+%d more)", f.Count-len(f.Examples))
			}
			fmt.Fprintf(b, "  - e.g. %s%s\n", strings.Join(f.Examples, ", "), more)
		}
	}
	fmt.Fprintln(b)
}

func renderMarkdownCoverage(b *strings.Builder, m reportModel) {
	if len(m.Coverage) == 0 {
		return
	}
	fmt.Fprintln(b, "## Coverage gaps — collections NOT audited")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "These were not read, so their absence from the blockers above is unproven. Investigate before trusting a clean result.")
	fmt.Fprintln(b)
	for _, g := range m.Coverage {
		fmt.Fprintf(b, "- `%s` — %s\n", g.Path, g.Reason)
	}
	fmt.Fprintln(b)
}
