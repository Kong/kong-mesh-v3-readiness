// Package reportmodel names the JSON contracts kuma3-preflight emits: Report
// (the CP-audit report) and Classification (the --classify output). Both are
// stable, versioned shapes — --from-json reloads Report verbatim, and every
// renderer (JSON/HTML/Markdown) draws from the same struct. docs/openapi.yaml
// is generated from these types by tools/openapigen; run `go generate ./...`
// after changing them.
//
// The CP-audit types below are aliases of their counterparts in the importable
// preflight package, which owns them (it defines RenderJSON/RenderHTML on
// Report). Prefer importing preflight directly; these aliases exist so code
// written against reportmodel keeps compiling. Classification has no preflight
// counterpart — it stays defined here, in classification.go.
package reportmodel

import "github.com/Kong/kong-mesh-v3-readiness/preflight"

// Report is the canonical, serializable form of a CP-audit report.
type Report = preflight.Report

// ControlPlane identifies the audited control plane.
type ControlPlane = preflight.ControlPlane

// Summary is the finding-count rollup shown at the top of a report.
type Summary = preflight.Summary

// Finding is one deprecation/blocker/advisory item, merged by (Severity, Category, Title).
type Finding = preflight.Finding

// CoverageGap is a collection that could not be audited — for example a 404 on a resource list.
type CoverageGap = preflight.CoverageGap

// ManualCheck is one upgrade item the CP API cannot surface. Its UnmarshalJSON
// accepts the v3 object form or the v2 bare-string form, mapping a legacy string
// to Title so --from-json still renders older reports.
type ManualCheck = preflight.ManualCheck
