package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// sampleReport builds a report exercising both severities, the example cap, a
// coverage gap, parse errors and system findings.
func sampleReport() *report {
	r := &report{
		cp:             cpIndex{Product: "Kuma", Version: "2.9.0", Mode: "zone"},
		meshes:         []string{"default", "legacy"},
		parseErrors:    1,
		systemFindings: 2,
		manual:         []string{"Enable unified naming", "Disable inbound tags"},
	}
	r.add(blocker, "Mesh object settings", "Inline mTLS on Mesh", "Migrate mtls.", "legacy (mtls)")
	// 12 occurrences > exampleCap(10): exercises the "+N more" truncation.
	for i := 0; i < 12; i++ {
		r.add(blocker, "Policy `from` field", "MeshTimeout uses `from`", "Rewrite from.", "default/t")
	}
	r.add(blocker, "MeshService mode", "meshServices.mode is not Exclusive", "Use Exclusive.", "default")
	r.add(info, "Zone proxies", "zoneingresses present", "Superseded.", "zi-1")
	r.addGap("/meshes/default/meshpassthroughs", "endpoint returned 404 — NOT audited")
	return r
}

func TestToModelSummaryAndStatus(t *testing.T) {
	m := sampleReport().toModel("2026-06-17T10:00:00Z")
	if m.Status != statusBlockers {
		t.Fatalf("status = %q, want %q", m.Status, statusBlockers)
	}
	if m.Summary.Blockers != 14 { // 1 + 12 + 1 (MeshService mode)
		t.Errorf("blockers = %d, want 14", m.Summary.Blockers)
	}
	if m.Summary.Info != 1 {
		t.Errorf("info = %d, want 1", m.Summary.Info)
	}
	if m.Summary.CoverageGaps != 1 || m.Summary.ParseErrors != 1 {
		t.Errorf("coverageGaps/parseErrors = %d/%d, want 1/1", m.Summary.CoverageGaps, m.Summary.ParseErrors)
	}
	// Findings must be globally sorted by (severity, group, category, title).
	if len(m.Findings) < 2 || m.Findings[0].Severity != "blocker" {
		t.Fatalf("first finding should be a blocker, got %+v", m.Findings)
	}
}

func TestToModelGroups(t *testing.T) {
	m := sampleReport().toModel("")
	want := map[string]string{
		"Inline mTLS on Mesh":                groupMeshObject,
		"meshServices.mode is not Exclusive": groupMeshObject,
		"MeshTimeout uses `from`":            groupPolicies,
		"zoneingresses present":              groupOther,
	}
	for _, f := range m.Findings {
		if g, ok := want[f.Title]; ok && f.Group != g {
			t.Errorf("finding %q group = %q, want %q", f.Title, f.Group, g)
		}
	}
	// Blockers must be ordered group-by-group following groupOrder.
	lastIdx := -1
	for _, f := range m.Findings {
		if f.Severity != "blocker" {
			continue
		}
		if idx := groupIndex(f.Group); idx < lastIdx {
			t.Errorf("findings not ordered by group at %q (idx %d after %d)", f.Title, idx, lastIdx)
		} else {
			lastIdx = idx
		}
	}
}

func TestRenderMarkdownGolden(t *testing.T) {
	got := renderMarkdown(sampleReport().toModel(""))
	for _, want := range []string{
		"# Kuma 3.0 Upgrade Pre-flight Report",
		"- Control plane: Kuma 2.9.0 (mode: zone)",
		"- Meshes scanned: default, legacy",
		"- Findings: 14 blockers, 1 info",
		"- Unparseable resources: 1",
		"- Includes 2 CP-managed (policy-role: system) resource(s) — update these before upgrading",
		"## Blockers — must resolve before upgrading",
		"### Mesh object",
		"#### Mesh object settings",
		"### Policies",
		"#### Policy `from` field",
		"### Other", // info section groups the Zone proxies finding
		"- **MeshTimeout uses `from`** — 12 found. Rewrite from.",
		"… (+2 more)", // 12 occurrences, capped at 10 examples
		"## Coverage gaps — collections NOT audited",
		"- `/meshes/default/meshpassthroughs` — endpoint returned 404 — NOT audited",
		"- [ ] Enable unified naming",
		"_Source of truth: `docs/deprecated-features.md`._",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, got)
		}
	}
	if strings.Index(got, "### Mesh object") > strings.Index(got, "### Policies") {
		t.Error("groups out of order: Mesh object should precede Policies")
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	m := sampleReport().toModel("2026-06-17T10:00:00Z")
	out, err := renderJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadModelBytes([]byte(out))
	if err != nil {
		t.Fatalf("reloading rendered JSON: %v", err)
	}
	again, err := renderJSON(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if out != again {
		t.Errorf("JSON not idempotent across a round-trip")
	}
}

func TestRenderHTMLIsSelfContainedAndSafe(t *testing.T) {
	m := sampleReport().toModel("2026-06-17T10:00:00Z")
	html, err := renderHTML(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(html, "<!doctype html>") || !strings.Contains(html, "</html>") {
		t.Error("HTML is not a complete document")
	}
	// json.Marshal escapes <,>,& so the embedded payload cannot break out of the
	// <script> tag: the only </script> must be the one closing the data block.
	_, tail, ok := strings.Cut(html, `<script id="report-data" type="application/json">`)
	if !ok {
		t.Fatal("missing data script tag")
	}
	data, _, _ := strings.Cut(tail, "</script>")
	if strings.Contains(data, "</script>") {
		t.Error("embedded JSON contains a raw </script> — unsafe injection")
	}
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Error("HTML references an external URL; it must be fully self-contained")
	}
}

func TestNormalizeFormat(t *testing.T) {
	cases := map[string]string{"": "markdown", "md": "markdown", "MARKDOWN": "markdown", "json": "json", "HTML": "html", "htm": "html"}
	for in, want := range cases {
		got, err := normalizeFormat(in)
		if err != nil || got != want {
			t.Errorf("normalizeFormat(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeFormat("pdf"); err == nil {
		t.Error("normalizeFormat(pdf) should error")
	}
}

func TestFailureModel(t *testing.T) {
	m := failureModel("http://cp:5681", errExample{}, "")
	if m.Status != statusFailed || m.Error == "" {
		t.Errorf("failure model = %+v", m)
	}
	if exitForStatus(m.Status) != 2 {
		t.Error("failed status must map to exit 2")
	}
}

type errExample struct{}

func (errExample) Error() string { return "boom" }

// loadModelBytes mirrors loadModel for an in-memory payload (no file I/O).
func loadModelBytes(b []byte) (reportModel, error) {
	var m reportModel
	if err := json.Unmarshal(b, &m); err != nil {
		return reportModel{}, err
	}
	return m, nil
}
