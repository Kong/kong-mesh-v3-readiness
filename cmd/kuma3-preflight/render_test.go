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

// TestAllowedToTargetRefKinds guards the 3.0 `to[].targetRef` contract: `Mesh`
// (all outbound — the canonical default-policy form, and the only kind valid for
// MeshGateway-targeted policies), the Mesh*Service kinds and `MeshHTTPRoute` stay
// valid; only the subset/selector kinds and `MeshGateway` are removed. Flagging a
// still-valid kind (e.g. `Mesh`) would be a false-positive blocker.
func TestAllowedToTargetRefKinds(t *testing.T) {
	for _, k := range []string{"Mesh", "MeshService", "MeshExternalService", "MeshMultiZoneService", "MeshHTTPRoute"} {
		if !allowedToTargetRefKinds[k] {
			t.Errorf("%s must be a valid to[].targetRef kind in 3.0 (flagging it is a false positive)", k)
		}
	}
	for _, k := range []string{"MeshSubset", "MeshServiceSubset", "MeshGateway"} {
		if allowedToTargetRefKinds[k] {
			t.Errorf("%s is removed from to[].targetRef in 3.0 and must still be flagged", k)
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
		"#### Mesh object settings", // Mesh object has 2 categories → subheaders shown
		"### Policies",              // single-category group → no redundant subheader
		"### Other",                 // info section groups the Zone proxies finding
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
	// A single-category group must not repeat the category as a subheading.
	if strings.Contains(got, "#### Policy `from` field") {
		t.Error("single-category group should not render a redundant category subheader")
	}
}

// TestNormalizeModelOldPayload guards the --from-json path for reports written
// before the group field existed: such a model has no Group and is sorted only by
// category, so groups interleave. normalizeModel must make them group-contiguous so
// markdown (which streams group headers) and HTML (which buckets by group) agree.
func TestNormalizeModelOldPayload(t *testing.T) {
	m := reportModel{
		Schema: reportSchema, Tool: toolName, Status: statusBlockers,
		Meshes: []string{}, Coverage: []coverageModel{}, Manual: []string{},
		Findings: []findingModel{ // category-sorted, no Group → Data plane interleaves Mesh object
			{Severity: "blocker", Category: "Dataplane probes", Title: "p", Detail: "d", Count: 1, Examples: []string{"x/p"}},
			{Severity: "blocker", Category: "Mesh object settings", Title: "m", Detail: "d", Count: 1, Examples: []string{"y (mtls)"}},
			{Severity: "blocker", Category: "reachableServices", Title: "r", Detail: "d", Count: 1, Examples: []string{"z/r"}},
		},
	}
	normalizeModel(&m)

	lastIdx, prevGroup := -1, ""
	seen := map[string]bool{}
	for _, f := range m.Findings {
		if f.Group == "" {
			t.Fatalf("group not populated for %q", f.Title)
		}
		if f.Group != prevGroup {
			if seen[f.Group] {
				t.Errorf("group %q is not contiguous after normalize", f.Group)
			}
			seen[f.Group] = true
			prevGroup = f.Group
		}
		if idx := groupIndex(f.Group); idx < lastIdx {
			t.Errorf("groups out of canonical order at %q", f.Title)
		} else {
			lastIdx = idx
		}
	}
	if md := renderMarkdown(m); strings.Count(md, "### "+groupDataPlane) != 1 {
		t.Errorf("group heading %q must appear exactly once, got %d\n---\n%s",
			groupDataPlane, strings.Count(md, "### "+groupDataPlane), md)
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
