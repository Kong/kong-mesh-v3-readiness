package main

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
	// doc is a Kong Mesh documentation URL explaining the 3.0 replacement API or
	// feature for this finding (empty when there is no replacement to point at,
	// e.g. an unparseable spec or a coverage note).
	doc      string
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
	// total counts every finding occurrence recorded (sum of finding counts). It
	// lets a caller detect whether a resource it just processed produced any
	// finding, without scanning the merged findings slice.
	total  int
	manual []manualCheck
	// k8sObserved is set once the audit positively observes Kubernetes anywhere in
	// the estate (a standalone/zone CP on k8s, a k8s zone behind a global, or a
	// dataplane labeled kuma.io/env=kubernetes). It gates the k8s-only manual
	// checks so a Universal-only run is not handed Kubernetes reminders.
	k8sObserved bool
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

// add records one occurrence of a finding with no documentation link — for
// advisory/info items, coverage notes and unparseable specs that have no 3.0
// replacement API to point at. Most blockers use addDoc instead.
func (r *report) add(sev severity, category, title, detail, example string) {
	r.addDoc(sev, category, title, detail, "", example)
}

// addDoc records one occurrence of a finding, merging by (severity, category,
// title) and accumulating an example reference (capped). doc is a Kong Mesh
// documentation URL explaining the 3.0 replacement; it is taken from the first
// occurrence (identical (severity, category, title) tuples carry the same doc).
func (r *report) addDoc(sev severity, category, title, detail, doc, example string) {
	r.total++
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
		doc: doc, count: 1, examples: []string{example},
	})
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
