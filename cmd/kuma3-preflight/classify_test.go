package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture writes a file under dir, creating parent directories.
func writeFixture(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildSourceFixture lays out a miniature e2e tree exercising each detection path:
// an inline-YAML removed resource (subject), a builder/inline Mesh field, an
// off-subject removed resource, and a clean file.
func buildSourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "trafficroute/traffic_route.go", `package trafficroute
const r = `+"`"+`
type: TrafficRoute
name: route-all
mesh: trafficroute
`+"`"+`
`)
	writeFixture(t, root, "mtls/mtls.go", `package mtls
const m = `+"`"+`
type: Mesh
name: mtls
mtls:
  enabledBackend: ca-1
`+"`"+`
var _ = MTLSMeshUniversal("mtls")
var _ = samples.MeshDefaultBuilder().WithEnabledMTLSBackend("ca-1")
`)
	writeFixture(t, root, "matching/matching.go", `package matching
const f = `+"`"+`
type: FaultInjection
name: fi-1
mesh: matching
`+"`"+`
`)
	writeFixture(t, root, "clean/clean.go", `package clean
const ok = `+"`"+`
type: MeshTrafficPermission
name: mtp
`+"`"+`
`)
	return root
}

func featureByName(m classificationModel, name string) (featureModel, bool) {
	for _, f := range m.Features {
		if f.Name == name {
			return f, true
		}
	}
	return featureModel{}, false
}

func usageByKind(f featureModel, kind string) (usageModel, bool) {
	for _, u := range f.Usages {
		if u.Kind == kind {
			return u, true
		}
	}
	return usageModel{}, false
}

func TestScanSourceClassification(t *testing.T) {
	ci := newClassIndex()
	if err := ci.scanSource(buildSourceFixture(t)); err != nil {
		t.Fatal(err)
	}
	m := ci.toModel("src", "", "")

	if _, ok := featureByName(m, "clean"); ok {
		t.Error("a feature with only non-deprecated resources must not be flagged")
	}

	tr, ok := featureByName(m, "trafficroute")
	if !ok {
		t.Fatal("trafficroute feature missing")
	}
	if tr.Recommendation != recRemove {
		t.Errorf("trafficroute: want %q (subject is a removed resource), got %q", recRemove, tr.Recommendation)
	}
	u, ok := usageByKind(tr, "TrafficRoute")
	if !ok || !u.Removable {
		t.Fatalf("trafficroute should record a removable TrafficRoute usage, got %+v", tr.Usages)
	}
	if len(u.Sources) != 1 || u.Sources[0] != "static" {
		t.Errorf("want static source, got %v", u.Sources)
	}

	mtls, ok := featureByName(m, "mtls")
	if !ok {
		t.Fatal("mtls feature missing")
	}
	if mtls.Recommendation != recRewrite {
		t.Errorf("mtls: inline mTLS is scaffolding, want %q, got %q", recRewrite, mtls.Recommendation)
	}
	if mu, ok := usageByKind(mtls, "Mesh.mtls"); !ok || mu.Removable || mu.Count < 1 {
		t.Errorf("mtls should record a non-removable Mesh.mtls usage (inline field + builder), got %+v", mtls.Usages)
	}

	matching, ok := featureByName(m, "matching")
	if !ok {
		t.Fatal("matching feature missing")
	}
	if matching.Recommendation != recRewrite {
		t.Errorf("matching uses FaultInjection off-subject, want %q, got %q", recRewrite, matching.Recommendation)
	}
}

// TestMarkerCatalogInSync guarantees every removed mesh-scoped kind the live
// auditor knows about (legacyMeshScoped) has a matching source marker, so the
// scanner can never silently miss a kind the auditor flags.
func TestMarkerCatalogInSync(t *testing.T) {
	byKind := map[string]deprecatedMarker{}
	for _, mk := range deprecatedMarkers() {
		byKind[mk.kind] = mk
	}
	for _, lt := range legacyMeshScoped {
		mk, ok := byKind[lt.kind]
		if !ok {
			t.Errorf("legacy kind %q has no source marker", lt.kind)
			continue
		}
		if !mk.removable {
			t.Errorf("marker for removed resource %q must be removable", lt.kind)
		}
		if mk.category != "Removed resource" {
			t.Errorf("marker %q: want category %q, got %q", lt.kind, "Removed resource", mk.category)
		}
		if mk.replacement != lt.replacement {
			t.Errorf("marker %q replacement out of sync: %q vs %q", lt.kind, mk.replacement, lt.replacement)
		}
	}
}

// writeSnapshot writes a preflight JSON report (the dynamic-capture artifact).
func writeSnapshot(t *testing.T, dir, name string, findings []findingModel) {
	t.Helper()
	m := reportModel{
		Schema: reportSchema, Tool: toolName, Status: statusBlockers,
		Meshes: []string{}, Findings: findings, Coverage: []coverageModel{}, Manual: []string{},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, dir, name, string(b))
}

func TestIngestReportsMergeAndDelta(t *testing.T) {
	ci := newClassIndex()
	// Static scan first so dynamic findings can map onto known features.
	if err := ci.scanSource(buildSourceFixture(t)); err != nil {
		t.Fatal(err)
	}

	reports := t.TempDir()
	// A removed resource attributed by its mesh ("trafficroute" -> static feature).
	removed := findingModel{
		Severity: "blocker", Category: "Removed resources",
		Title: "TrafficRoute (removed in 3.0)", Count: 1, Examples: []string{"trafficroute/route-all"},
	}
	infoFinding := findingModel{Severity: "info", Category: "Zone proxies", Title: "zoneingresses present", Count: 1}
	// CP-level findings describe the e2e CP itself, not a test's resource — excluded.
	cpFinding := findingModel{
		Severity: "blocker", Category: cpConfigCategory, Title: "Delta xDS not enabled",
		Count: 1, Examples: []string{"experimental.deltaXds=false"},
	}
	// The shared CP is cumulative + parallel, so the same finding recurs across
	// snapshots; dedupe by (feature, kind, example) must collapse it.
	writeSnapshot(t, reports, "0001-trafficroute-should-route.json", []findingModel{removed, infoFinding, cpFinding})
	writeSnapshot(t, reports, "0002-some-other-spec.json", []findingModel{removed, cpFinding})

	if err := ci.ingestReports(reports); err != nil {
		t.Fatal(err)
	}
	m := ci.toModel("src", reports, "")

	tr, ok := featureByName(m, "trafficroute")
	if !ok {
		t.Fatal("trafficroute feature missing after ingest")
	}
	u, ok := usageByKind(tr, "TrafficRoute")
	if !ok {
		t.Fatal("TrafficRoute usage missing")
	}
	if !contains(u.Sources, "static") || !contains(u.Sources, "dynamic") {
		t.Errorf("dynamic finding should merge with the static TrafficRoute usage, sources=%v", u.Sources)
	}
	// Static contributes 1 hit; the dynamic finding recurs in both snapshots but must
	// dedupe to a single dynamic hit — total 2, not 3.
	if u.Count != 2 {
		t.Errorf("want count 2 (1 static + 1 deduped dynamic), got %d", u.Count)
	}
	// The info finding must never become a deprecation, and CP-level config findings
	// must not create a feature (they are environment properties, not test usage).
	for _, bad := range []string{"experimental.deltaXds=false", "(unknown)"} {
		if _, ok := featureByName(m, bad); ok {
			t.Errorf("CP-level / unknown finding leaked into the classification as feature %q", bad)
		}
	}
	for _, f := range m.Features {
		if _, ok := usageByKind(f, "Delta xDS not enabled"); ok {
			t.Errorf("CP-level finding must be excluded from per-test classification (feature %q)", f.Name)
		}
	}
}

func TestRenderClassificationFormats(t *testing.T) {
	ci := newClassIndex()
	if err := ci.scanSource(buildSourceFixture(t)); err != nil {
		t.Fatal(err)
	}
	m := ci.toModel("src", "", "")

	md := renderClassificationMarkdown(m)
	for _, want := range []string{recRemove, recRewrite, "trafficroute", "TrafficRoute", "MeshHTTPRoute", "Mesh.mtls"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}

	js, err := renderClassificationJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var round classificationModel
	if err := json.Unmarshal([]byte(js), &round); err != nil {
		t.Fatalf("classification JSON does not round-trip: %v", err)
	}
	if round.Schema != classificationSchema {
		t.Errorf("schema = %q, want %q", round.Schema, classificationSchema)
	}

	htmlOut := renderClassificationHTML(m)
	if strings.Contains(htmlOut, "http://") || strings.Contains(htmlOut, "https://") {
		t.Error("classification HTML references an external URL; it must be fully self-contained")
	}
	if !strings.Contains(htmlOut, "trafficroute") {
		t.Error("classification HTML missing scanned feature")
	}
}

func TestLoadModelValidatesSchema(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "good.json", `{"schema":"`+reportSchema+`","status":"clean","meshes":[],"findings":[],"coverageGaps":[],"manualChecks":[]}`)
	if _, err := loadModel(filepath.Join(dir, "good.json")); err != nil {
		t.Errorf("a valid report schema must be accepted, got: %v", err)
	}
	// A non-empty but foreign schema (unrelated JSON, or a classification report fed
	// where a report is expected, or a missing schema) must be rejected.
	for name, payload := range map[string]string{
		"foreign":        `{"schema":"unrelated/v1"}`,
		"classification": `{"schema":"` + classificationSchema + `"}`,
		"no-schema":      `{"foo":1}`,
	} {
		writeFixture(t, dir, name+".json", payload)
		if _, err := loadModel(filepath.Join(dir, name+".json")); err == nil {
			t.Errorf("loadModel accepted a %s payload; want rejection", name)
		}
	}
}

func TestRunClassifyRequiresInput(t *testing.T) {
	if code := runClassify("", "", "markdown", "", ""); code != 2 {
		t.Errorf("runClassify with no inputs: want exit 2, got %d", code)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
