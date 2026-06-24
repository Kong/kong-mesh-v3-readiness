package main

import (
	"encoding/json"
	"fmt"
	"html"
	"path/filepath"
	"sort"
	"strings"
)

// classificationModel is the canonical, serializable form of a classification run.
// As with reportModel, every format renders from this one structure and the JSON
// shape is the stable contract.
type classificationModel struct {
	Schema      string         `json:"schema"`
	Tool        string         `json:"tool"`
	GeneratedAt string         `json:"generatedAt,omitempty"`
	SourceDir   string         `json:"sourceDir,omitempty"`
	ReportsDir  string         `json:"reportsDir,omitempty"`
	Summary     classSummary   `json:"summary"`
	Features    []featureModel `json:"features"`
}

type classSummary struct {
	Features         int `json:"features"`
	Remove           int `json:"remove"`
	Rewrite          int `json:"rewrite"`
	DeprecatedUsages int `json:"deprecatedUsages"`
}

type featureModel struct {
	Name           string       `json:"name"`
	Recommendation string       `json:"recommendation"`
	Usages         []usageModel `json:"usages"`
}

type usageModel struct {
	Kind        string   `json:"kind"`
	Category    string   `json:"category"`
	Replacement string   `json:"replacement"`
	Removable   bool     `json:"removable"`
	Count       int      `json:"count"`
	Sources     []string `json:"sources"`
	Examples    []string `json:"examples"`
}

func recRank(rec string) int {
	switch rec {
	case recRemove:
		return 0
	case recRewrite:
		return 1
	default:
		return 2
	}
}

// toModel projects the accumulated index onto the serializable model with stable
// ordering: features sorted by recommendation (remove first) then name; usages by
// removable (resources first) then kind; sources and examples sorted/deterministic.
func (ci *classIndex) toModel(sourceDir, reportsDir, generatedAt string) classificationModel {
	m := classificationModel{
		Schema: classificationSchema, Tool: toolName, GeneratedAt: generatedAt,
		SourceDir: sourceDir, ReportsDir: reportsDir, Features: []featureModel{},
	}
	for _, name := range ci.featureNames() {
		f := ci.features[name]
		fm := featureModel{Name: name, Recommendation: f.recommendation(), Usages: []usageModel{}}

		kinds := make([]string, 0, len(f.usages))
		for k := range f.usages {
			kinds = append(kinds, k)
		}
		sort.Slice(kinds, func(i, j int) bool {
			ui, uj := f.usages[kinds[i]], f.usages[kinds[j]]
			if ui.removable != uj.removable {
				return ui.removable
			}
			return kinds[i] < kinds[j]
		})
		for _, k := range kinds {
			u := f.usages[k]
			srcs := make([]string, 0, len(u.sources))
			for s := range u.sources {
				srcs = append(srcs, s)
			}
			sort.Strings(srcs)
			fm.Usages = append(fm.Usages, usageModel{
				Kind: u.kind, Category: u.category, Replacement: u.replacement,
				Removable: u.removable, Count: u.count, Sources: srcs,
				Examples: append([]string{}, u.examples...),
			})
			m.Summary.DeprecatedUsages += u.count
		}
		m.Features = append(m.Features, fm)
		m.Summary.Features++
		switch fm.Recommendation {
		case recRemove:
			m.Summary.Remove++
		case recRewrite:
			m.Summary.Rewrite++
		}
	}
	sort.SliceStable(m.Features, func(i, j int) bool {
		if ri, rj := recRank(m.Features[i].Recommendation), recRank(m.Features[j].Recommendation); ri != rj {
			return ri < rj
		}
		return m.Features[i].Name < m.Features[j].Name
	})
	return m
}

func renderClassification(format string, m classificationModel) (string, error) {
	switch format {
	case "json":
		return renderClassificationJSON(m)
	case "html":
		return renderClassificationHTML(m), nil
	default:
		return renderClassificationMarkdown(m), nil
	}
}

func renderClassificationJSON(m classificationModel) (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// renderClassificationMarkdown emits one collapsible env block (GitHub-flavored
// markdown): an `<details open>` wrapper whose summary carries the env's headline
// counts, a per-recommendation summary table, then a nested `<details>` per test
// suite. The e2e workflow concatenates one of these per env under a single H1, so
// the combined job summary is three expandable env sections rather than a wall of
// ~2,000 lines. Severity (🟥 remove / 🟧 rewrite / ✅ clean) and category emoji give
// the report at-a-glance structure.
func renderClassificationMarkdown(m classificationModel) string {
	var b strings.Builder
	env := classEnvLabel(m)

	headSev := "🟧"
	switch {
	case m.Summary.Features == 0:
		headSev = "✅"
	case m.Summary.Remove > 0:
		headSev = "🟥"
	}

	fmt.Fprintln(&b, "<details open>")
	fmt.Fprintf(&b, "<summary>%s <b><code>%s</code></b> — %d suites · 🟥 %d remove/replace · 🟧 %d rewrite · %d usages</summary>\n\n",
		headSev, html.EscapeString(env), m.Summary.Features, m.Summary.Remove, m.Summary.Rewrite, m.Summary.DeprecatedUsages)
	fmt.Fprintf(&b, "> 📂 `%s` &nbsp;·&nbsp; 📸 `%s`\n\n", or(m.SourceDir, "(none)"), or(m.ReportsDir, "(none)"))

	if m.Summary.Features == 0 {
		fmt.Fprintln(&b, "✅ No deprecated-feature usage detected in the scanned sources/snapshots.")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "_Source of truth: `docs/deprecated-features.md` / `audit.go`._")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "</details>")
		return b.String()
	}

	removeUsages, rewriteUsages := recUsageTotals(m)
	fmt.Fprintln(&b, "| Recommendation | Suites | Usages |")
	fmt.Fprintln(&b, "|---|--:|--:|")
	fmt.Fprintf(&b, "| 🟥 Remove / replace | %d | %d |\n", m.Summary.Remove, removeUsages)
	fmt.Fprintf(&b, "| 🟧 Rewrite | %d | %d |\n\n", m.Summary.Rewrite, rewriteUsages)

	renderMarkdownRecSection(&b, m, recRemove, "🟥",
		"Remove / replace — the test's subject is a resource removed in 3.0")
	renderMarkdownRecSection(&b, m, recRewrite, "🟧",
		"Rewrite — uses a deprecated feature as scaffolding for an unrelated test")

	fmt.Fprintln(&b, "_Source of truth: `docs/deprecated-features.md` / `audit.go`._")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "</details>")
	return b.String()
}

func renderMarkdownRecSection(b *strings.Builder, m classificationModel, rec, sev, heading string) {
	section := make([]featureModel, 0)
	for _, f := range m.Features {
		if f.Recommendation == rec {
			section = append(section, f)
		}
	}
	if len(section) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s %s\n\n", sev, heading)
	for _, f := range section {
		usages := 0
		for _, u := range f.Usages {
			usages += u.Count
		}
		fmt.Fprintf(b, "<details><summary>%s <b>%s</b> — %d finding(s) · %d usage(s)</summary>\n\n",
			sev, html.EscapeString(f.Name), len(f.Usages), usages)
		for _, u := range f.Usages {
			repl := ""
			if u.Replacement != "" {
				repl = " → **" + u.Replacement + "**"
			}
			fmt.Fprintf(b, "- %s **%s** _(%s)_ — %d× · `%s`%s\n",
				categoryEmoji(u.Category), u.Kind, u.Category, u.Count, strings.Join(u.Sources, ", "), repl)
			if len(u.Examples) > 0 {
				more := ""
				if u.Count > len(u.Examples) {
					more = fmt.Sprintf(", … (+%d more)", u.Count-len(u.Examples))
				}
				fmt.Fprintf(b, "  - e.g. %s%s\n", joinInlineCode(u.Examples), more)
			}
		}
		fmt.Fprintln(b)
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
	}
}

// classEnvLabel names the env this classification covers, taken from the scanned
// source tree (test/e2e_env/<env>) or, failing that, the snapshots dir.
func classEnvLabel(m classificationModel) string {
	switch {
	case m.SourceDir != "":
		return filepath.Base(m.SourceDir)
	case m.ReportsDir != "":
		return filepath.Base(m.ReportsDir)
	default:
		return "report"
	}
}

// recUsageTotals sums deprecated-usage counts per recommendation for the summary table.
func recUsageTotals(m classificationModel) (remove, rewrite int) {
	for _, f := range m.Features {
		n := 0
		for _, u := range f.Usages {
			n += u.Count
		}
		if f.Recommendation == recRemove {
			remove += n
		} else {
			rewrite += n
		}
	}
	return remove, rewrite
}

// categoryEmoji picks a glyph for a usage category so bullets scan by kind.
func categoryEmoji(category string) string {
	switch {
	case strings.Contains(category, "Removed"):
		return "⛔"
	case strings.Contains(category, "Dataplane"):
		return "🛰️"
	case strings.Contains(category, "Mesh"):
		return "🕸️"
	case strings.Contains(category, "targetRef"),
		strings.Contains(category, "proxyTypes"),
		strings.Contains(category, "from"):
		return "🎯"
	case strings.Contains(category, "Relocated"):
		return "📦"
	case strings.Contains(category, "OpenTelemetry"):
		return "📡"
	case strings.Contains(category, "RFC"):
		return "🏷️"
	default:
		return "⚙️"
	}
}

// joinInlineCode renders each example as inline code, comma-joined.
func joinInlineCode(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = "`" + s + "`"
	}
	return strings.Join(q, ", ")
}

// renderClassificationHTML emits a fully self-contained page (inline CSS, no JS, no
// network requests) so it opens offline from file://. All dynamic values are
// HTML-escaped; the page never references an external URL (a test enforces this).
func renderClassificationHTML(m classificationModel) string {
	var b strings.Builder
	b.WriteString(classHTMLHead)
	fmt.Fprintf(&b, "<h1>Kuma e2e — Kuma 3.0 deprecation classification</h1>\n")
	fmt.Fprintf(&b, "<p class=\"meta\">Source tree: <code>%s</code> · Dynamic snapshots: <code>%s</code></p>\n",
		html.EscapeString(or(m.SourceDir, "(none)")), html.EscapeString(or(m.ReportsDir, "(none)")))
	fmt.Fprintf(&b, "<p class=\"meta\">%d feature(s) flagged — <b>%d</b> to remove/replace, <b>%d</b> to rewrite, %d deprecated usages.</p>\n",
		m.Summary.Features, m.Summary.Remove, m.Summary.Rewrite, m.Summary.DeprecatedUsages)

	if m.Summary.Features == 0 {
		b.WriteString("<p class=\"ok\">No deprecated-feature usage detected.</p>\n")
		b.WriteString(classHTMLTail)
		return b.String()
	}

	b.WriteString("<table>\n<thead><tr><th>Feature</th><th>Recommendation</th><th>Kind</th><th>Category</th><th>Count</th><th>Source</th><th>Replacement</th><th>Examples</th></tr></thead>\n<tbody>\n")
	for _, f := range m.Features {
		recClass := "rewrite"
		if f.Recommendation == recRemove {
			recClass = "remove"
		}
		for i, u := range f.Usages {
			feat, rec := "", ""
			if i == 0 {
				feat = html.EscapeString(f.Name)
				rec = fmt.Sprintf("<span class=\"badge %s\">%s</span>", recClass, html.EscapeString(f.Recommendation))
			}
			fmt.Fprintf(&b, "<tr class=\"%s\"><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td class=\"ex\">%s</td></tr>\n",
				recClass, feat, rec,
				html.EscapeString(u.Kind), html.EscapeString(u.Category), u.Count,
				html.EscapeString(strings.Join(u.Sources, ", ")),
				html.EscapeString(u.Replacement),
				html.EscapeString(strings.Join(u.Examples, ", ")))
		}
	}
	b.WriteString("</tbody>\n</table>\n")
	b.WriteString(classHTMLTail)
	return b.String()
}

const classHTMLHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kuma e2e — Kuma 3.0 deprecation classification</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#2a3038;--text:#e6edf3;--muted:#8b949e;
  --remove:#f85149;--remove-bg:rgba(248,81,73,.10);--rewrite:#d29922;--rewrite-bg:rgba(210,153,34,.10);--ok:#3fb950}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:22px;margin:0 0 8px}
.meta{color:var(--muted);font-size:13px;margin:2px 0}
.ok{color:var(--ok)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}
table{width:100%;border-collapse:collapse;margin-top:18px;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;border-bottom:2px solid var(--border)}
td.ex{color:var(--muted);font-size:12px;max-width:360px;word-break:break-word}
tr.remove td{background:var(--remove-bg)}
tr.rewrite td{background:var(--rewrite-bg)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}
.badge.remove{color:var(--remove);border:1px solid var(--remove)}
.badge.rewrite{color:var(--rewrite);border:1px solid var(--rewrite)}
</style>
</head>
<body>
<div class="wrap">
`

const classHTMLTail = `<p class="meta">Source of truth: <code>docs/deprecated-features.md</code> / <code>audit.go</code></p>
</div>
</body>
</html>
`
