package main

import (
	"fmt"
	"sort"
	"strings"
)

type severity int

const (
	blocker severity = iota
	warning
	info
)

type finding struct {
	severity severity
	category string
	title    string
	detail   string
	count    int
	examples []string
}

type coverageGap struct {
	path   string
	reason string
}

type report struct {
	cp             cpIndex
	meshes         []string
	findings       []finding
	coverage       []coverageGap
	parseErrors    int
	systemFindings int
	manual         []string
}

// incomplete reports whether the audit could not fully observe the CP — either a
// collection was unreadable (coverage gap) or a resource spec failed to parse.
// Such a run must not read as a clean pass.
func (r *report) incomplete() bool {
	return len(r.coverage) > 0 || r.parseErrors > 0
}

// addGap records a collection that could not be audited, so the report
// distinguishes "absent" from "not observed".
func (r *report) addGap(path, reason string) {
	r.coverage = append(r.coverage, coverageGap{path: path, reason: reason})
}

// add records one occurrence of a finding, merging by (severity, category, title)
// and accumulating an example reference (capped).
func (r *report) add(sev severity, category, title, detail, example string) {
	for i := range r.findings {
		f := &r.findings[i]
		if f.severity == sev && f.category == category && f.title == title {
			f.count++
			if len(f.examples) < exampleCap {
				f.examples = append(f.examples, example)
			}
			return
		}
	}
	r.findings = append(r.findings, finding{
		severity: sev, category: category, title: title, detail: detail,
		count: 1, examples: []string{example},
	})
}

func (r *report) countBlockers() int {
	n := 0
	for _, f := range r.findings {
		if f.severity == blocker {
			n += f.count
		}
	}
	return n
}

func (r *report) count(sev severity) int {
	n := 0
	for _, f := range r.findings {
		if f.severity == sev {
			n += f.count
		}
	}
	return n
}

func (r *report) render() string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Kuma 3.0 Upgrade Pre-flight Report")
	fmt.Fprintln(&b)
	product := r.cp.Product
	if product == "" {
		product = "Kuma"
	}
	fmt.Fprintf(&b, "- Control plane: %s %s", product, r.cp.Version)
	if r.cp.Mode != "" {
		fmt.Fprintf(&b, " (mode: %s)", r.cp.Mode)
	}
	fmt.Fprintln(&b)
	meshes := "none"
	if len(r.meshes) > 0 {
		meshes = strings.Join(r.meshes, ", ")
	}
	fmt.Fprintf(&b, "- Meshes scanned: %s\n", meshes)
	fmt.Fprintf(&b, "- Findings: %d blockers, %d warnings, %d info\n", r.count(blocker), r.count(warning), r.count(info))
	if len(r.coverage) > 0 {
		fmt.Fprintf(&b, "- Coverage gaps: %d collection(s) could not be audited\n", len(r.coverage))
	}
	if r.parseErrors > 0 {
		fmt.Fprintf(&b, "- Unparseable resources: %d\n", r.parseErrors)
	}
	if r.systemFindings > 0 {
		fmt.Fprintf(&b, "- Includes %d CP-managed (policy-role: system) resource(s) — update these before upgrading\n", r.systemFindings)
	}
	fmt.Fprintln(&b)

	switch {
	case r.countBlockers() > 0:
		// Blocker count is already in the header; the section below lists them.
	case r.incomplete():
		fmt.Fprintln(&b, "⚠️ No blockers found, but the audit was inconclusive (coverage gaps and/or unparseable resources) — this is NOT a clean bill of health.")
	default:
		fmt.Fprintln(&b, "✅ No blocking resources or Mesh settings found. Review the warnings and manual checks below before upgrading.")
	}
	fmt.Fprintln(&b)

	r.renderSection(&b, "Blockers — must resolve before upgrading", blocker)
	r.renderSection(&b, "Warnings — should resolve", warning)
	r.renderCoverage(&b)
	r.renderSection(&b, "Informational", info)

	fmt.Fprintln(&b, "## Manual checks (not detectable via the CP API)")
	fmt.Fprintln(&b)
	for _, m := range r.manual {
		fmt.Fprintf(&b, "- [ ] %s\n", m)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "_Source of truth: `docs/deprecated-features.md`._")
	return b.String()
}

func (r *report) renderCoverage(b *strings.Builder) {
	if len(r.coverage) == 0 {
		return
	}
	gaps := append([]coverageGap(nil), r.coverage...)
	sort.SliceStable(gaps, func(i, j int) bool { return gaps[i].path < gaps[j].path })
	fmt.Fprintln(b, "## Coverage gaps — collections NOT audited")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "These were not read, so their absence from the blockers above is unproven. Investigate before trusting a clean result.")
	fmt.Fprintln(b)
	for _, g := range gaps {
		fmt.Fprintf(b, "- `%s` — %s\n", g.path, g.reason)
	}
	fmt.Fprintln(b)
}

func (r *report) renderSection(b *strings.Builder, heading string, sev severity) {
	section := make([]finding, 0)
	for _, f := range r.findings {
		if f.severity == sev {
			section = append(section, f)
		}
	}
	if len(section) == 0 {
		return
	}
	// Group by category, stable by title within a category.
	sort.SliceStable(section, func(i, j int) bool {
		if section[i].category != section[j].category {
			return section[i].category < section[j].category
		}
		return section[i].title < section[j].title
	})

	fmt.Fprintf(b, "## %s\n\n", heading)
	lastCategory := ""
	for _, f := range section {
		if f.category != lastCategory {
			fmt.Fprintf(b, "### %s\n\n", f.category)
			lastCategory = f.category
		}
		fmt.Fprintf(b, "- **%s** — %d found. %s\n", f.title, f.count, f.detail)
		if len(f.examples) > 0 {
			more := ""
			if f.count > len(f.examples) {
				more = fmt.Sprintf(", … (+%d more)", f.count-len(f.examples))
			}
			fmt.Fprintf(b, "  - e.g. %s%s\n", strings.Join(f.examples, ", "), more)
		}
	}
	fmt.Fprintln(b)
}
