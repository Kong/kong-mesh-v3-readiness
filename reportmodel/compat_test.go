package reportmodel_test

import (
	"testing"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
	"github.com/Kong/kong-mesh-v3-readiness/reportmodel"
)

// The CP-audit types must stay *aliases* of the preflight ones, not copies: an
// importer mixing both paths (or passing a preflight.Report where a
// reportmodel.Report is expected) has to keep compiling. Redeclaring any of them
// as a distinct struct breaks these assignments at compile time.
var (
	_ reportmodel.Report       = preflight.Report{}
	_ reportmodel.ControlPlane = preflight.ControlPlane{}
	_ reportmodel.Summary      = preflight.Summary{}
	_ reportmodel.Finding      = preflight.Finding{}
	_ reportmodel.CoverageGap  = preflight.CoverageGap{}
	_ reportmodel.ManualCheck  = preflight.ManualCheck{}

	_ preflight.Report       = reportmodel.Report{}
	_ preflight.ControlPlane = reportmodel.ControlPlane{}
	_ preflight.Summary      = reportmodel.Summary{}
	_ preflight.Finding      = reportmodel.Finding{}
	_ preflight.CoverageGap  = reportmodel.CoverageGap{}
	_ preflight.ManualCheck  = reportmodel.ManualCheck{}
)

// TestAliasedReportRendersThroughPreflight pins the behavior the aliases buy:
// a Report built with the reportmodel names still carries preflight's methods
// and its legacy-manual-check UnmarshalJSON.
func TestAliasedReportRendersThroughPreflight(t *testing.T) {
	r := reportmodel.Report{
		Schema:       preflight.SchemaVersion,
		Tool:         preflight.ToolName,
		Status:       preflight.StatusBlockers,
		ControlPlane: reportmodel.ControlPlane{Product: "Kuma", Version: "2.14.0"},
		Meshes:       []string{"default"},
		Summary:      reportmodel.Summary{Blockers: 1},
		Findings: []reportmodel.Finding{{
			Severity: preflight.SeverityBlocker,
			Group:    "Removed resources",
			Category: "removed",
			Title:    "TrafficPermission removed in 3.0",
			Detail:   "migrate to MeshTrafficPermission",
			Count:    1,
			Examples: []string{"default/allow-all"},
		}},
		Coverage: []reportmodel.CoverageGap{},
		Manual:   []reportmodel.ManualCheck{{Title: "check Helm values"}},
	}

	js, err := r.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	back, err := preflight.ParseReport([]byte(js))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if back.Status != preflight.StatusBlockers {
		t.Errorf("status = %q, want %q", back.Status, preflight.StatusBlockers)
	}
	if len(back.Manual) != 1 || back.Manual[0].Title != "check Helm values" {
		t.Errorf("manual checks = %+v, want one titled %q", back.Manual, "check Helm values")
	}
	if _, err := r.RenderHTML(); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
}
