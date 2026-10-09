package preflight

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestRunsTargetMajor(t *testing.T) {
	for in, want := range map[string]bool{
		"3.0.0":                    true,
		"3.0.0-preview.v6bcf212e8": true,
		"v3.1.2":                   true,
		"4.0.0":                    true,
		"2.14.6":                   false,
		"2.14.6-preview.vda8d1fd8": false,
		"0.0.0-preview.vbea63cd57": false,
		"dev":                      false,
		"":                         false,
	} {
		if got := runsTargetMajor(in); got != want {
			t.Errorf("runsTargetMajor(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestAuditSkipsControlPlaneOn3x audits a 3.x CP whose removed endpoints answer
// 404 and whose /config lacks the 2.x settings: the audit must stop after GET /
// with a single info finding instead of gaps and false blockers.
func TestAuditSkipsControlPlaneOn3x(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	rep := auditVersion(t, "2.14.6", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			writeJSON(w, []byte(`{"product":"Kong Mesh","version":"3.0.0-preview.v6bcf212e8","mode":"global"}`))
		},
		"/traffic-permissions": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			http.NotFound(w, r)
		},
	})
	if len(paths) != 1 || paths[0] != "/" {
		t.Errorf("requests = %v, want only GET /", paths)
	}
	if got := rep.status(); got != StatusClean {
		t.Errorf("status = %q, want %q", got, StatusClean)
	}
	if len(rep.coverage) != 0 {
		t.Errorf("coverage gaps = %v, want none", rep.coverage)
	}
	if len(rep.findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the 3.x note", rep.findings)
	}
	f := rep.findings[0]
	if f.severity != info || f.title != "Control plane already runs 3.x" ||
		!hasExample(f, "control plane (3.0.0-preview.v6bcf212e8)") {
		t.Errorf("finding = %+v", f)
	}
	if len(rep.manual) != 0 {
		t.Errorf("manual checks = %d, want none on a 3.x CP", len(rep.manual))
	}
}

// TestAuditKeepsDevBuildsAudited keeps a master build ("0.0.0-preview") on the
// full audit: its version says nothing about the major it will ship as.
func TestAuditKeepsDevBuildsAudited(t *testing.T) {
	rep := auditVersion(t, "2.14.6", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"product":"Kuma","version":"0.0.0-preview.vbea63cd57","mode":"zone"}`))
		},
	})
	for _, f := range rep.findings {
		if f.title == "Control plane already runs 3.x" {
			t.Fatalf("dev build short-circuited: %+v", f)
		}
	}
	if len(rep.manual) == 0 {
		t.Errorf("dev build should get the full audit, including manual checks")
	}
}

// TestZoneOn3xSkipsConfigFindings: a 2.x global with a zone already on 3.x must
// not read that zone's missing 2.x settings as disabled, nor flag its version.
func TestZoneOn3xSkipsConfigFindings(t *testing.T) {
	zones := `{"total":2,"items":[
		{"type":"ZoneInsight","name":"zone-new","zoneInsight":{"subscriptions":[{"config":"{\"mode\":\"zone\"}","version":{"kumaCp":{"version":"3.0.0-preview.v6bcf212e8"}}}]}},
		{"type":"ZoneInsight","name":"zone-old","zoneInsight":{"subscriptions":[{"config":"{\"mode\":\"zone\",\"experimental\":{\"deltaXds\":false}}","version":{"kumaCp":{"version":"2.14.6"}}}]}}
	],"next":null}`
	rep := auditVersion(t, "2.14.6", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.6","mode":"global"}`))
		},
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"mode":"global","environment":"universal"}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(zones))
		},
	})
	var note bool
	for _, f := range rep.findings {
		for _, ex := range f.examples {
			if f.title == "Zone control plane already runs 3.x" && ex == "zone zone-new (3.0.0-preview.v6bcf212e8)" {
				note = true
				continue
			}
			if f.severity == blocker && containsZone(ex, "zone-new") {
				t.Errorf("3.x zone flagged: %q %q", f.title, ex)
			}
		}
	}
	if !note {
		t.Errorf("no 3.x zone note; findings=%+v", rep.findings)
	}
	if _, ok := findTitle(rep, "Delta xDS not enabled"); !ok {
		t.Errorf("2.x zone-old must still be audited; findings=%+v", rep.findings)
	}
}

// TestDataplaneOn3xSkipsFeatureChecks: kuma-dp 3.x does not advertise the 2.14
// runtime features, which must not turn into blockers.
func TestDataplaneOn3xSkipsFeatureChecks(t *testing.T) {
	dp := func(version string) map[string]any {
		return map[string]any{
			"type": "DataplaneOverview", "mesh": "default", "name": "dp-" + version,
			"dataplaneInsight": map[string]any{
				"subscriptions": []any{map[string]any{"version": map[string]any{"kumaDp": map[string]any{"version": version, "kumaCpCompatible": true}}}},
				"metadata":      map[string]any{"features": []any{"feature-tcp-accesslog-via-named-pipe"}},
			},
		}
	}
	m := auditResponses(t, map[string]string{"/dataplanes+insights": listBody(t, dp("3.0.0-preview.v6bcf212e8"), dp("2.14.6"))})
	f, ok := findFinding(m, "blocker", "Dataplane features", "Dataplane is not using unified resource naming")
	if !ok {
		t.Fatalf("2.14 proxy should still be flagged; findings=%+v", m.Findings)
	}
	if f.Count != 1 {
		t.Errorf("count = %d, want only the 2.14 proxy; examples=%v", f.Count, f.Examples)
	}
}

func containsZone(example, zone string) bool {
	return example == "zone "+zone || strings.HasPrefix(example, "zone "+zone+":")
}

func findTitle(r *collector, title string) (rawFinding, bool) {
	for _, f := range r.findings {
		if f.title == title {
			return f, true
		}
	}
	return rawFinding{}, false
}
