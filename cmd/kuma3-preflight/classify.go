package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The classifier answers a different question from the live audit: given the Kuma
// e2e test tree (and, optionally, per-spec preflight snapshots captured during an
// e2e run), which tests exercise features removed or deprecated in Kuma 3.0 — so
// the team can decide which e2e tests to remove/replace vs rewrite. It reuses the
// same deprecation catalog the live auditor uses (legacyMeshScoped, audit.go), so
// the two never drift.

const classificationSchema = "kuma3-preflight-classification/v1"

// Per-feature recommendation labels.
const (
	recRemove  = "REMOVE/REPLACE"
	recRewrite = "REWRITE"
)

// deprecatedMarker is a source-detectable signal that a test exercises a feature
// removed or deprecated in 3.0. patterns are OR-ed; requires are AND-ed gates that
// must all be present in the file for the marker to fire (used to scope an inline
// field like `metrics:` to a resource that actually defines a Mesh/Dataplane).
type deprecatedMarker struct {
	kind        string
	category    string
	replacement string
	// removable marks a feature that is a standalone resource gone in 3.0 (its test
	// is a removal candidate). false = a deprecated/relocated field, usually
	// incidental scaffolding (rewrite candidate).
	removable bool
	patterns  []*regexp.Regexp
	requires  []*regexp.Regexp
}

func (m deprecatedMarker) match(data []byte) []int {
	for _, r := range m.requires {
		if !r.Match(data) {
			return nil
		}
	}
	var lines []int
	for _, p := range m.patterns {
		for _, loc := range p.FindAllIndex(data, -1) {
			// bytes.Count avoids allocating a string per match on large files.
			lines = append(lines, 1+bytes.Count(data[:loc[0]], []byte{'\n'}))
		}
	}
	sort.Ints(lines)
	return dedupInts(lines)
}

func compileAll(pats []string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		res = append(res, regexp.MustCompile(p))
	}
	return res
}

func marker(kind, category, replacement string, removable bool, patterns, requires []string) deprecatedMarker {
	return deprecatedMarker{
		kind: kind, category: category, replacement: replacement, removable: removable,
		patterns: compileAll(patterns), requires: compileAll(requires),
	}
}

// deprecatedMarkers builds the scan catalog. The removed mesh-scoped kinds come
// from legacyMeshScoped (audit.go) so the scanner stays in lockstep with the live
// auditor; helper/builder identifiers (which apply a resource without a literal
// `type:` line) are added per kind.
func deprecatedMarkers() []deprecatedMarker {
	helperPatterns := map[string][]string{
		"TrafficPermission": {`\bTrafficPermissionUniversal\b`},
		"TrafficRoute":      {`\bTrafficRouteUniversal\b`},
		"Timeout":           {`\bTimeoutUniversal\b`},
		"CircuitBreaker":    {`\bCircuitBreakerUniversal\b`},
		"Retry":             {`\bRetryUniversal\b`},
	}
	var markers []deprecatedMarker
	for _, lt := range legacyMeshScoped {
		pats := []string{`(?m)^\s*type:\s*` + regexp.QuoteMeta(lt.kind) + `\b`}
		pats = append(pats, helperPatterns[lt.kind]...)
		markers = append(markers, marker(lt.kind, "Removed resource", lt.replacement, true, pats, nil))
	}

	meshDefines := []string{`(?m)^\s*type:\s*Mesh\b`}
	dpDefines := []string{`(?m)^\s*type:\s*Dataplane\b`}
	markers = append(markers,
		// Inline mTLS on Mesh is detected by its specific field (`enabledBackend:`)
		// and the framework's mTLS-mesh helpers/builders; no Mesh gate needed.
		marker("Mesh.mtls", "Mesh field", "MeshIdentity + MeshTrust", false,
			[]string{
				`(?m)^\s*enabledBackend:`, `\bMTLSMesh(Universal|Kubernetes)\b`,
				`\bWith(Enabled|Builtin|Inline)MTLSBackend\b`, `\bWithPermissiveMTLSBackends\b`,
			}, nil),
		marker("Mesh.metrics", "Mesh field", "MeshMetric policy", false,
			[]string{`(?m)^\s*metrics:`}, meshDefines),
		marker("Mesh.tracing", "Mesh field", "MeshTrace policy", false,
			[]string{`(?m)^\s*tracing:`}, meshDefines),
		marker("Mesh.logging", "Mesh field", "MeshAccessLog policy", false,
			[]string{`(?m)^\s*logging:`}, meshDefines),
		marker("Mesh.routing.zoneEgress", "Mesh field", "(removed)", false,
			[]string{`(?m)^\s*zoneEgress:\s*true\b`}, meshDefines),
		marker("Mesh.constraints", "Mesh field", "(removed)", false,
			[]string{`(?m)^\s*constraints:`}, meshDefines),
		marker("Mesh.passthrough", "Mesh field", "MeshPassthrough", false,
			[]string{`(?m)^\s*passthrough:`}, meshDefines),
		marker("targetRef.proxyTypes", "Policy field", "(removed — gateway support dropped)", false,
			[]string{`(?m)^\s*proxyTypes:`}, nil),
		marker("Dataplane.reachableServices", "Dataplane field", "reachableBackends (MeshService)", false,
			[]string{`(?m)^\s*reachableServices:`}, nil),
		marker("Dataplane.probes", "Dataplane field", "app-probe-proxy", false,
			[]string{`(?m)^\s*probes:`}, dpDefines),
		marker("Dataplane.gateway", "Dataplane field", "delegated gateway", false,
			[]string{`(?m)^\s*gateway:`}, dpDefines),
	)
	return markers
}

// classIndex accumulates deprecated-feature usage per e2e feature (the test
// subdirectory). Static source hits and dynamic snapshot findings merge by kind.
type classIndex struct {
	markers  []deprecatedMarker
	features map[string]*classFeature
	// scanned is every feature dir seen by scanSource, even those with zero marker
	// hits, so dynamic findings can fold a mesh onto its feature dir regardless.
	scanned map[string]bool
}

type classFeature struct {
	name   string
	usages map[string]*classUsage
}

type classUsage struct {
	kind, category, replacement string
	removable                   bool
	count                       int
	sources                     map[string]bool
	examples                    []string
}

func newClassIndex() *classIndex {
	return &classIndex{markers: deprecatedMarkers(), features: map[string]*classFeature{}, scanned: map[string]bool{}}
}

func (ci *classIndex) addUsage(feature, kind, category, replacement string, removable bool, source, example string) {
	f := ci.features[feature]
	if f == nil {
		f = &classFeature{name: feature, usages: map[string]*classUsage{}}
		ci.features[feature] = f
	}
	u := f.usages[kind]
	if u == nil {
		u = &classUsage{kind: kind, category: category, replacement: replacement, removable: removable, sources: map[string]bool{}}
		f.usages[kind] = u
	}
	u.count++
	u.sources[source] = true
	if example != "" && len(u.examples) < exampleCap {
		u.examples = append(u.examples, example)
	}
}

func (ci *classIndex) featureNames() []string {
	names := make([]string, 0, len(ci.features))
	for n := range ci.features {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// scannedFeatures returns every feature dir scanSource walked, including dirs with
// no deprecated usage — the set a dynamic mesh name is mapped onto.
func (ci *classIndex) scannedFeatures() []string {
	names := make([]string, 0, len(ci.scanned))
	for n := range ci.scanned {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// scanSource walks the e2e source tree and records every deprecated-feature marker
// hit, grouped by the top-level subdirectory under root (one feature per dir, which
// matches the test/e2e_env/<env>/<feature>/ layout).
func (ci *classIndex) scanSource(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".yaml", ".yml":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		feature := featureName(rel)
		ci.scanned[feature] = true
		for _, mk := range ci.markers {
			lines := mk.match(data)
			for _, ln := range lines {
				ci.addUsage(feature, mk.kind, mk.category, mk.replacement, mk.removable, "static", fmt.Sprintf("%s:%d", rel, ln))
			}
		}
		return nil
	})
}

// featureName maps a path relative to the scan root to its feature: the first path
// segment (the per-feature subdir), or "(root)" for files directly under root.
func featureName(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) <= 1 {
		return "(root)"
	}
	return parts[0]
}

// ingestReports folds per-spec preflight JSON snapshots (captured during an e2e run)
// into the index. The e2e suite runs many specs in parallel against ONE shared,
// cumulatively-mutated CP, so spec/file ordering is not a reliable attribution key —
// but each finding's example references are mesh-qualified (`mesh/name`), and a test's
// mesh is named after its feature. So each example resource is attributed by its mesh
// (mapped onto a known static feature when possible). Findings are deduped across
// snapshots by (feature, kind, example). CP-level findings (the e2e CP's own config /
// meshServices.mode) are environment properties, not test-authored usage, so they are
// excluded from this per-test view.
func (ci *classIndex) ingestReports(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	known := ci.scannedFeatures() // every scanned feature dir, to map a mesh name onto its feature
	seen := map[string]bool{}
	for _, name := range files {
		m, err := loadModel(filepath.Join(dir, name))
		if err != nil {
			// A non-report .json in the snapshots dir (e.g. a previously written
			// classification report) is skipped, not fatal.
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", name, err)
			continue
		}
		for _, f := range m.Findings {
			if f.Severity != blocker.String() {
				continue // warning/info findings (advisories, sampling-coverage notes) are not deprecations
			}
			if cpLevelCategory(f.Category) {
				continue // CP/global config, not a per-test resource usage
			}
			kind, removable, category, replacement := dynamicUsage(f)
			examples := f.Examples
			if len(examples) == 0 {
				examples = []string{""}
			}
			for _, ex := range examples {
				feat := featureForExample(ex, known)
				key := feat + "|" + kind + "|" + ex
				if seen[key] {
					continue
				}
				seen[key] = true
				ci.addUsage(feat, kind, category, replacement, removable, "dynamic", ex)
			}
		}
	}
	return nil
}

// cpLevelCategory reports whether a finding describes the control plane / global
// itself rather than a resource a test authored — excluded from the per-test
// classification (still surfaced by a live audit).
func cpLevelCategory(c string) bool {
	switch c {
	case cpConfigCategory, "MeshService mode":
		return true
	}
	return false
}

// markersByKind indexes the static catalog once so dynamic findings can adopt a
// marker's category/replacement when they map to the same kind.
var markersByKind = func() map[string]deprecatedMarker {
	m := make(map[string]deprecatedMarker)
	for _, mk := range deprecatedMarkers() {
		m[mk.kind] = mk
	}
	return m
}()

// fieldFindingToKind maps a live-audit finding TITLE for an inline Mesh/Dataplane
// field to the static marker kind, so the same deprecation merges into one row
// instead of splitting (e.g. audit "Inline mTLS on Mesh" == static "Mesh.mtls", which
// otherwise renders as two kinds and loses the replacement string). Removed resources
// are handled separately (their title carries the kind); the targetRef/`from` policy
// findings have no static marker and stay keyed by title.
var fieldFindingToKind = map[string]string{
	"Inline mTLS on Mesh":              "Mesh.mtls",
	"Inline metrics on Mesh":           "Mesh.metrics",
	"Inline tracing on Mesh":           "Mesh.tracing",
	"Inline logging on Mesh":           "Mesh.logging",
	"routing.zoneEgress on Mesh":       "Mesh.routing.zoneEgress",
	"Passthrough on Mesh":              "Mesh.passthrough",
	"Mesh membership constraints":      "Mesh.constraints",
	"Dataplane uses reachableServices": "Dataplane.reachableServices",
	"Dataplane has a gateway section":  "Dataplane.gateway",
	"Dataplane has a probes section":   "Dataplane.probes",
}

// dynamicUsage projects a live-audit finding onto the classifier's (kind, removable)
// taxonomy so dynamic findings merge with static markers of the same kind.
func dynamicUsage(f findingModel) (string, bool, string, string) {
	if f.Category == "Removed resources" {
		kind := strings.TrimSuffix(f.Title, " (removed in 3.0)")
		return kind, true, "Removed resource", replacementFor(kind)
	}
	if k, ok := fieldFindingToKind[f.Title]; ok {
		mk := markersByKind[k]
		return k, mk.removable, mk.category, mk.replacement
	}
	return f.Title, false, f.Category, ""
}

func replacementFor(kind string) string {
	for _, lt := range legacyMeshScoped {
		if lt.kind == kind {
			return lt.replacement
		}
	}
	return ""
}

// featureForExample maps a finding's example reference to a feature. Examples are
// mesh-qualified ("mesh/name") or field-tagged ("mesh (field)"); the leading token is
// the mesh, whose name is a test's feature. The mesh is mapped onto a known static
// feature when one is a normalized substring match (so "external-service-base" folds
// into "externalservices"); otherwise the mesh name itself is the feature.
func featureForExample(ex string, known []string) string {
	s := ex
	if i := strings.Index(s, " ("); i >= 0 {
		s = s[:i] // drop " (field)" / " (system…)" annotations
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i] // mesh from "mesh/name"
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "(unknown)"
	}
	n := normalizeName(s)
	best := ""
	for _, k := range known {
		kn := normalizeName(k)
		if kn == "" {
			continue
		}
		if (n == kn || strings.Contains(n, kn) || strings.Contains(kn, n)) && len(kn) > len(normalizeName(best)) {
			best = k
		}
	}
	if best != "" {
		return best
	}
	return s
}

func (f *classFeature) recommendation() string {
	for _, u := range f.usages {
		if u.removable && subjectMatches(f.name, u.kind) {
			return recRemove
		}
	}
	return recRewrite
}

// subjectMatches reports whether a removed resource kind IS the test's subject (the
// feature dir is named after it), e.g. feature "trafficroute" + kind "TrafficRoute".
// Such a test only exists to exercise a removed resource: a removal candidate.
func subjectMatches(feature, kind string) bool {
	return normalizeName(feature) == normalizeName(kind)
}

func normalizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func dedupInts(in []int) []int {
	out := in[:0]
	prev := -1
	for _, v := range in {
		if v != prev {
			out = append(out, v)
			prev = v
		}
	}
	return out
}

// runClassify is the --classify entry point: scan source and/or ingest snapshots,
// then render the classification in the requested format.
func runClassify(sourceDir, reportsDir, format, out, generatedAt string) int {
	if sourceDir == "" && reportsDir == "" {
		fmt.Fprintln(os.Stderr, "error: --classify needs --source-dir and/or --reports-dir")
		return 2
	}
	ci := newClassIndex()
	if sourceDir != "" {
		if err := ci.scanSource(sourceDir); err != nil {
			fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", sourceDir, err)
			return 2
		}
	}
	if reportsDir != "" {
		if err := ci.ingestReports(reportsDir); err != nil {
			fmt.Fprintf(os.Stderr, "error reading snapshots in %s: %v\n", reportsDir, err)
			return 2
		}
	}
	content, err := renderClassification(format, ci.toModel(sourceDir, reportsDir, generatedAt))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if err := emit(out, content); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", out, err)
		return 2
	}
	return 0
}
