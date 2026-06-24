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
	reportSchema = "kuma3-preflight/v2"
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
	Info           int `json:"info"`
	CoverageGaps   int `json:"coverageGaps"`
	ParseErrors    int `json:"parseErrors"`
	SystemFindings int `json:"systemFindings"`
}

type findingModel struct {
	Severity string   `json:"severity"`
	Group    string   `json:"group"`
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
	"Mesh object settings":     groupMeshObject,
	"MeshService mode":         groupMeshObject,
	"Policy `from` field":      groupPolicies,
	"Top-level targetRef kind": groupPolicies,
	"`to` targetRef kind":      groupPolicies,
	"targetRef proxyTypes":     groupPolicies,
	"Relocated policy fields":  groupPolicies,
	"OpenTelemetry endpoint":   groupPolicies,
	"Removed resources":        groupRemovedResources,
	"reachableServices":        groupDataPlane,
	"Gateway in Dataplane":     groupDataPlane,
	"Dataplane probes":         groupDataPlane,
	"Dataplane metrics":        groupDataPlane,
	"Dataplane version":        groupDataPlane,
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

// groupOf resolves a finding's group, recomputing from category when the model
// predates the group field (e.g. an older --from-json payload).
func groupOf(f findingModel) string {
	if f.Group != "" {
		return f.Group
	}
	return categoryGroup(f.Category)
}

// severityRank orders severities for rendering: blocker before info, unknown last.
func severityRank(sev string) int {
	switch sev {
	case blocker.String():
		return 0
	case info.String():
		return 1
	default:
		return 2
	}
}

// normalizeModel makes a model canonical for rendering: every finding gets its
// group, and findings are sorted (severity, group order, category, title) so each
// group is contiguous. Renderers rely on that contiguity, so both fresh audits and
// --from-json (including older payloads written before the group field existed)
// render identically — preserving the one-model/three-renderers contract.
func normalizeModel(m *reportModel) {
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
			Info:           r.count(info),
			CoverageGaps:   len(r.coverage),
			ParseErrors:    r.parseErrors,
			SystemFindings: r.systemFindings,
		},
		Findings: []findingModel{},
		Coverage: []coverageModel{},
		Manual:   append([]string{}, r.manual...),
	}

	for _, f := range r.findings {
		m.Findings = append(m.Findings, findingModel{
			Severity: f.severity.String(),
			Group:    categoryGroup(f.category),
			Category: f.category,
			Title:    f.title,
			Detail:   f.detail,
			Count:    f.count,
			Examples: append([]string{}, f.examples...),
		})
	}
	normalizeModel(&m)

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
	fmt.Fprintf(&b, "- Findings: %d blockers, %d info\n", m.Summary.Blockers, m.Summary.Info)
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
		fmt.Fprintln(&b, "✅ No blocking resources or Mesh settings found. Review the informational notes and manual checks below before upgrading.")
	}
	fmt.Fprintln(&b)

	renderMarkdownSection(&b, m, "Blockers — must resolve before upgrading", "blocker")
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
	// Count distinct categories per group so a single-category group can skip the
	// redundant category subheading (the group heading already names it).
	catsPerGroup := map[string]map[string]struct{}{}
	for _, f := range section {
		g := groupOf(f)
		if catsPerGroup[g] == nil {
			catsPerGroup[g] = map[string]struct{}{}
		}
		catsPerGroup[g][f.Category] = struct{}{}
	}
	fmt.Fprintf(b, "## %s\n\n", heading)
	lastGroup, lastCategory := "", ""
	for _, f := range section {
		g := groupOf(f)
		if g != lastGroup {
			fmt.Fprintf(b, "### %s\n\n", g)
			lastGroup, lastCategory = g, ""
		}
		if len(catsPerGroup[g]) > 1 && f.Category != lastCategory {
			fmt.Fprintf(b, "#### %s\n\n", f.Category)
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
