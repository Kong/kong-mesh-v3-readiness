// Package preflight audits a running Kuma (or Kong Mesh) control plane over its
// REST API and reports which resources and settings must change before upgrading
// to Kuma 3.0. It is the engine behind the kuma3-preflight CLI
// (cmd/kuma3-preflight), extracted so other Go programs can run the same audit
// directly.
//
// Audit performs no I/O other than HTTP requests to the audited control plane: it
// never prints, logs, reads flags, or calls os.Exit. See docs/deprecated-features.md
// in the module root for the source of truth behind every check.
package preflight

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// defaultTimeout bounds the default HTTP client built when Options.HTTPClient is nil.
const defaultTimeout = 60 * time.Second

// Options configures one Audit call against a running control plane.
type Options struct {
	// Address is the control plane's REST API base URL, e.g. http://localhost:5681.
	// Required.
	Address string
	// Token is a bearer token for the CP API. It is needed to read /config on an
	// access-controlled Kong Mesh CP; without it, /config is recorded as a
	// coverage gap rather than a hard failure.
	Token string
	// Mesh limits the audit to a single mesh. Empty audits every mesh.
	Mesh string
	// InspectDataplanes caps how many dataplanes' Envoy config dumps are fetched
	// to detect removed features. 0 skips this expensive per-proxy inspection.
	InspectDataplanes int
	// LatestPatch is the latest 2.x patch to check control-plane (and connected
	// zone) version currency against, e.g. "2.14.7". Resolving this value (for
	// example from the GitHub releases API) is the caller's responsibility —
	// this package makes no network calls beyond Address. An empty LatestPatch
	// degrades the version-currency check to a coverage gap (the run reports
	// inconclusive rather than a false-clean pass or a hard error).
	LatestPatch string
	// HTTPClient is used to reach the control plane. A nil value builds a
	// default client with a 60s timeout.
	HTTPClient *http.Client
	// ResourceReadLimit caps how many resource items one audit admits across all
	// collection reads. 0 or less disables the cap.
	ResourceReadLimit int
	// RequestHeaders are added to every control-plane audit request sent to
	// Address. These headers are cloned before use, built-in defaults fill only
	// missing values, and Token still overrides Authorization when non-empty.
	RequestHeaders http.Header
	// SkipAuditedControlPlaneVersionCheck excludes only the audited control
	// plane's own patch level from the version-currency check; connected zone
	// control planes are still checked. The report records the exclusion as an
	// info finding, so its absence is never read as a pass. Default false keeps
	// today's behavior of flagging the audited control plane.
	SkipAuditedControlPlaneVersionCheck bool
}

// Audit runs a full readiness audit against the control plane described by opts
// and returns the projected Report. The only error paths are hard failures (e.g.
// an invalid Address, an unreachable CP, or a non-Kuma endpoint) — anything the
// audit can degrade gracefully from (a 404, a parse failure, an unresolved
// LatestPatch) is recorded as a coverage gap or parse error on the returned
// Report instead, so the run reports status "inconclusive" rather than erroring.
func Audit(ctx context.Context, opts Options) (Report, error) {
	if opts.Address == "" {
		return Report{}, fmt.Errorf("preflight: Options.Address is required")
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	c, err := newClientWithHTTP(opts.Address, opts.Token, hc, opts.RequestHeaders)
	if err != nil {
		return Report{}, err
	}
	c.resourceReadCeil = newResourceReadBudget(opts.ResourceReadLimit)
	col, err := audit(ctx, c, auditOptions{
		meshFilter:        opts.Mesh,
		inspectDataplanes: opts.InspectDataplanes,
		// Version currency is always attempted; an empty LatestPatch alone (no
		// fetch error to distinguish, since fetching is now the caller's job)
		// degrades it to a coverage gap. See checkControlPlaneVersions.
		checkVersionCurrency: true,
		latestPatch:          opts.LatestPatch,
		skipAuditedCPVersion: opts.SkipAuditedControlPlaneVersionCheck,
		resourceReadLimit:    opts.ResourceReadLimit,
	})
	if err != nil {
		return Report{}, err
	}
	// GeneratedAt is left for the caller to stamp (see cmd/kuma3-preflight/main.go,
	// which measures "now" before starting the audit and assigns it afterward).
	return col.toModel(""), nil
}

// RemovedKind describes one mesh-scoped resource kind removed in Kuma 3.0.
// Policy marks a classic Kuma 1.x *policy* type (traffic-permissions, retries,
// …); the rest are networking/gateway resources.
type RemovedKind struct {
	WSPath      string
	Kind        string
	Replacement string
	Doc         string
	Policy      bool
}

// RemovedKinds returns the catalog of mesh-scoped resource kinds this package
// flags as removed in Kuma 3.0 — e.g. so an importer's own static scanner (like
// the CLI's --classify mode) can stay in lockstep with the live audit. The
// returned slice is a copy of the internal catalog; mutating it has no effect on
// future audits.
func RemovedKinds() []RemovedKind {
	out := make([]RemovedKind, len(legacyMeshScoped))
	for i, lt := range legacyMeshScoped {
		out[i] = RemovedKind{
			WSPath: lt.wsPath, Kind: lt.kind, Replacement: lt.replacement,
			Doc: lt.doc, Policy: lt.policy,
		}
	}
	return out
}
