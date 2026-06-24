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
	Global      []globalModel  `json:"global"`
	Features    []featureModel `json:"features"`
}

// globalModel is a cross-cutting deprecation: a non-removable field/policy/mesh
// setting recurring across many suites, fixed once centrally rather than per suite.
type globalModel struct {
	Kind        string `json:"kind"`
	Category    string `json:"category"`
	Replacement string `json:"replacement"`
	Removable   bool   `json:"removable"`
	Suites      int    `json:"suites"`
	Count       int    `json:"count"`
}

type classSummary struct {
	Features         int `json:"features"`
	Remove           int `json:"remove"`
	Rewrite          int `json:"rewrite"`
	DeprecatedUsages int `json:"deprecatedUsages"`
	GlobalMigrations int `json:"globalMigrations"`
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
	// Global marks a usage whose kind was lifted into the cross-cutting Global table;
	// per-suite renderers omit these to avoid repeating the same fix in every suite.
	Global bool `json:"global,omitempty"`
}

// globalSuiteThreshold: a non-removable deprecation seen in at least this many suites
// is a cross-cutting "global" migration (one centralized fix), lifted out of the
// per-suite view. Removed resources are never global — each is per-suite removal work.
const globalSuiteThreshold = 3

// computeGlobal aggregates non-removable usages recurring across >= globalSuiteThreshold
// suites into cross-cutting rows, returning the set of global kinds so the per-suite view
// can drop them. Order: most suites first, then most usages, then kind (deterministic).
func computeGlobal(features []featureModel) ([]globalModel, map[string]bool) {
	type agg struct {
		category, replacement string
		removable             bool
		suites, count         int
	}
	byKind := map[string]*agg{}
	for _, f := range features {
		for _, u := range f.Usages {
			if u.Removable {
				continue // removed resources stay per-suite removal work
			}
			a := byKind[u.Kind]
			if a == nil {
				a = &agg{category: u.Category, replacement: u.Replacement, removable: u.Removable}
				byKind[u.Kind] = a
			}
			a.suites++
			a.count += u.Count
		}
	}
	globalKinds := map[string]bool{}
	out := []globalModel{}
	for kind, a := range byKind {
		if a.suites < globalSuiteThreshold {
			continue
		}
		globalKinds[kind] = true
		out = append(out, globalModel{
			Kind: kind, Category: a.category, Replacement: a.replacement,
			Removable: a.removable, Suites: a.suites, Count: a.count,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Suites != out[j].Suites {
			return out[i].Suites > out[j].Suites
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Kind < out[j].Kind
	})
	return out, globalKinds
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
		if f == nil { // featureNames() returns existing keys, so this never fires; guards the deref for static analysis
			continue
		}
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
			if u == nil { // kinds are existing usage keys, so this never fires; guards the deref for static analysis
				continue
			}
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

	global, globalKinds := computeGlobal(m.Features)
	m.Global = global
	m.Summary.GlobalMigrations = len(global)
	for fi := range m.Features {
		for ui := range m.Features[fi].Usages {
			if globalKinds[m.Features[fi].Usages[ui].Kind] {
				m.Features[fi].Usages[ui].Global = true
			}
		}
	}
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
// counts, then a 🌐 Global-migrations table (cross-cutting fixes that recur across
// suites, lifted out once) followed by 📁 Per-suite tables listing only what is unique
// to each suite. The e2e workflow concatenates one of these per env under a single H1.
// Emojis are wayfinding only (one env-status glyph + one icon per section); tables carry
// no emoji so the data scans cleanly.
func renderClassificationMarkdown(m classificationModel) string {
	var b strings.Builder
	env := classEnvLabel(m)

	fmt.Fprintln(&b, "<details open>")
	fmt.Fprintf(&b, "<summary>%s <b><code>%s</code></b> — %d suites · %d remove · %d rewrite · %d usages</summary>\n\n",
		envStatusIcon(m), html.EscapeString(env), m.Summary.Features, m.Summary.Remove, m.Summary.Rewrite, m.Summary.DeprecatedUsages)
	fmt.Fprintf(&b, "> 📂 `%s` &nbsp;·&nbsp; 📸 `%s`\n\n", or(m.SourceDir, "(none)"), or(m.ReportsDir, "(none)"))

	if m.Summary.Features == 0 {
		fmt.Fprintln(&b, "✅ No deprecated-feature usage detected in the scanned sources/snapshots.")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "_Source of truth: `docs/deprecated-features.md` / `audit.go`._")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "</details>")
		return b.String()
	}

	renderMarkdownGlobal(&b, m)
	renderMarkdownPerSuite(&b, m)

	fmt.Fprintln(&b, "_Source of truth: `docs/deprecated-features.md` / `audit.go`._")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "</details>")
	return b.String()
}

// envStatusIcon is the single status glyph on the env headline: ✅ clean, ⛔ has
// removal candidates, ⚠️ rewrite-only. The only severity emoji in the report.
func envStatusIcon(m classificationModel) string {
	switch {
	case m.Summary.Features == 0:
		return "✅"
	case m.Summary.Remove > 0:
		return "⛔"
	default:
		return "⚠️"
	}
}

// renderMarkdownGlobal renders the cross-cutting migrations as one table (omitted when
// there are none). Each row is a fix applied once that clears usages in many suites.
func renderMarkdownGlobal(b *strings.Builder, m classificationModel) {
	if len(m.Global) == 0 {
		return
	}
	fmt.Fprintln(b, "#### 🌐 Global migrations — fix once, applies across suites")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| Deprecated | Replacement | Suites | Usages |")
	fmt.Fprintln(b, "|---|---|--:|--:|")
	for _, g := range m.Global {
		fmt.Fprintf(b, "| %s | %s | %d | %d |\n", mdCode(g.Kind), or(g.Replacement, "—"), g.Suites, g.Count)
	}
	fmt.Fprintln(b)
}

// renderMarkdownPerSuite renders one collapsible table per suite listing only its
// unique (non-global) findings. Suites whose findings are entirely covered by the
// global table are collapsed into a single trailing line instead of empty sections.
func renderMarkdownPerSuite(b *strings.Builder, m classificationModel) {
	fmt.Fprintln(b, "#### 📁 Per-suite findings — unique to each suite")
	fmt.Fprintln(b)
	var globalOnly []string
	wrote := false
	for _, f := range m.Features {
		uniq := uniqueUsages(f)
		if len(uniq) == 0 {
			globalOnly = append(globalOnly, f.Name)
			continue
		}
		wrote = true
		fmt.Fprintf(b, "<details><summary><code>%s</code> — %s · %d unique finding(s)</summary>\n\n",
			html.EscapeString(f.Name), recLabel(f.Recommendation), len(uniq))
		fmt.Fprintln(b, "| Kind | Category | Count | Sources | Replacement | Examples |")
		fmt.Fprintln(b, "|---|---|--:|---|---|---|")
		for _, u := range uniq {
			fmt.Fprintf(b, "| %s | %s | %d | %s | %s | %s |\n",
				mdCode(u.Kind), u.Category, u.Count, strings.Join(u.Sources, ", "),
				or(u.Replacement, "—"), previewExamples(u))
		}
		fmt.Fprintln(b)
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
	}
	if !wrote {
		fmt.Fprintln(b, "_No suite-specific findings — everything is covered by the global migrations above._")
		fmt.Fprintln(b)
	}
	if len(globalOnly) > 0 {
		coded := make([]string, len(globalOnly))
		for i, n := range globalOnly {
			coded[i] = "`" + n + "`"
		}
		fmt.Fprintf(b, "_%d suite(s) need only the global migrations above: %s_\n\n",
			len(globalOnly), strings.Join(coded, ", "))
	}
}

// uniqueUsages returns a feature's non-global usages — those the per-suite view shows.
func uniqueUsages(f featureModel) []usageModel {
	out := make([]usageModel, 0, len(f.Usages))
	for _, u := range f.Usages {
		if !u.Global {
			out = append(out, u)
		}
	}
	return out
}

// recLabel is the plain-text recommendation shown in a per-suite summary (no emoji).
func recLabel(rec string) string {
	if rec == recRemove {
		return "remove/replace"
	}
	return "rewrite"
}

// exampleShowCap bounds how many example refs a per-suite table cell shows inline
// before collapsing the remainder into a "+N more" suffix, keeping rows readable.
const exampleShowCap = 3

func previewExamples(u usageModel) string {
	if len(u.Examples) == 0 {
		return "—"
	}
	show := u.Examples
	if len(show) > exampleShowCap {
		show = show[:exampleShowCap]
	}
	s := joinInlineCode(show)
	if hidden := u.Count - len(show); hidden > 0 {
		s += fmt.Sprintf(", +%d more", hidden)
	}
	return s
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

// mdCode wraps a value as GitHub-flavored inline code, surviving backticks inside the
// value (some finding kinds embed `from`) by widening the fence per the CommonMark rule.
func mdCode(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	longest, cur := 0, 0
	for _, r := range s {
		if r == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
		} else {
			cur = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	return fence + " " + s + " " + fence
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
	fmt.Fprintf(&b, "<p class=\"meta\">%d feature(s) flagged — <b>%d</b> to remove/replace, <b>%d</b> to rewrite, %d deprecated usages · %d global migration(s).</p>\n",
		m.Summary.Features, m.Summary.Remove, m.Summary.Rewrite, m.Summary.DeprecatedUsages, m.Summary.GlobalMigrations)

	if m.Summary.Features == 0 {
		b.WriteString("<p class=\"ok\">No deprecated-feature usage detected.</p>\n")
		b.WriteString(classHTMLTail)
		return b.String()
	}

	if len(m.Global) > 0 {
		b.WriteString("<h2>Global migrations <span class=\"sub\">— fix once, applies across suites</span></h2>\n")
		b.WriteString("<table>\n<thead><tr><th>Deprecated</th><th>Replacement</th><th>Suites</th><th>Usages</th></tr></thead>\n<tbody>\n")
		for _, g := range m.Global {
			fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td>%s</td><td>%d</td><td>%d</td></tr>\n",
				html.EscapeString(g.Kind), html.EscapeString(or(g.Replacement, "—")), g.Suites, g.Count)
		}
		b.WriteString("</tbody>\n</table>\n")
	}

	b.WriteString("<h2>Per-suite findings <span class=\"sub\">— unique to each suite</span></h2>\n")
	b.WriteString("<table>\n<thead><tr><th>Feature</th><th>Recommendation</th><th>Kind</th><th>Category</th><th>Count</th><th>Source</th><th>Replacement</th><th>Examples</th></tr></thead>\n<tbody>\n")
	var globalOnly []string
	for _, f := range m.Features {
		uniq := uniqueUsages(f)
		if len(uniq) == 0 {
			globalOnly = append(globalOnly, f.Name)
			continue
		}
		recClass := "rewrite"
		if f.Recommendation == recRemove {
			recClass = "remove"
		}
		for i, u := range uniq {
			feat, rec := "", ""
			if i == 0 {
				feat = html.EscapeString(f.Name)
				rec = fmt.Sprintf("<span class=\"badge %s\">%s</span>", recClass, html.EscapeString(f.Recommendation))
			}
			fmt.Fprintf(&b, "<tr class=\"%s\"><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td class=\"ex\">%s</td></tr>\n",
				recClass, feat, rec,
				html.EscapeString(u.Kind), html.EscapeString(u.Category), u.Count,
				html.EscapeString(strings.Join(u.Sources, ", ")),
				html.EscapeString(or(u.Replacement, "—")),
				html.EscapeString(strings.Join(u.Examples, ", ")))
		}
	}
	b.WriteString("</tbody>\n</table>\n")
	if len(globalOnly) > 0 {
		fmt.Fprintf(&b, "<p class=\"meta\">%d suite(s) need only the global migrations above: %s</p>\n",
			len(globalOnly), html.EscapeString(strings.Join(globalOnly, ", ")))
	}
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
h2{font-size:17px;margin:28px 0 4px}
.sub{color:var(--muted);font-weight:400;font-size:13px}
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
