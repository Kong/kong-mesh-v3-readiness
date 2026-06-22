package main

type severity int

const (
	blocker severity = iota
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

func (r *report) count(sev severity) int {
	n := 0
	for _, f := range r.findings {
		if f.severity == sev {
			n += f.count
		}
	}
	return n
}
