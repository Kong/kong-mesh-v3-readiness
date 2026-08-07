# v3-readiness

`kuma3-preflight` checks whether a running **Kuma 2.x** control plane is ready to upgrade to
**Kuma 3.0**. It audits the control plane over its REST API and writes a report of everything
that must change first — removed resources, deprecated policy fields, settings that flip in
3.0 — as a self-contained HTML page (or JSON). Point it at one zone or at the global CP to
cover the whole multizone estate in a single run.

Built with the Go standard library only — no third-party dependencies.

## Install

```bash
# With Go:
go install github.com/Kong/kong-mesh-v3-readiness/cmd/kuma3-preflight@latest

# Or download a prebuilt binary (linux/darwin, amd64/arm64) from the Releases page:
#   https://github.com/Kong/kong-mesh-v3-readiness/releases
```

## Usage

```bash
# 1. Audit a control plane → self-contained HTML report
kuma3-preflight --address http://localhost:5681 --output report.html

# 2. Kubernetes zone CP: port-forward in the background, then audit (the default
#    --address is http://localhost:5681); pass --token to also audit /config
kubectl -n kuma-system port-forward svc/kuma-control-plane 5681:5681 &
kuma3-preflight --token "$KUMA_TOKEN" --output report.html

# 3. CI: capture JSON and gate on the exit code, render HTML offline later
kuma3-preflight --address http://localhost:5681 --format json --output report.json
kuma3-preflight --from-json report.json --format html --output report.html
```

Exit codes: `0` clean · `1` blockers found · `2` operational error · `3` inconclusive.

`--token` is optional, but Kong Mesh gates `GET /config` behind RBAC — without it that
endpoint is skipped (the run is inconclusive, exit 3), so pass a token to audit control-plane
settings. See the example report gallery in [`examples/`](examples/).

## Use it as a Go library

The audit engine behind the CLI is importable directly, so another Go program can run the
same audit without shelling out:

```bash
go get github.com/Kong/kong-mesh-v3-readiness/preflight
```

```go
import "github.com/Kong/kong-mesh-v3-readiness/preflight"

hc := &http.Client{Timeout: 30 * time.Second}
rep, err := preflight.Audit(ctx, preflight.Options{
	Address: "http://localhost:5681",
	// Latest 2.14 patch to check CP/zone version currency against. Resolving it is
	// the caller's job — leave it empty and that one check becomes a coverage gap,
	// which makes the whole report inconclusive.
	LatestPatch: "2.14.7",
	// Cap one audit's total collection reads. 0 leaves it unlimited.
	ResourceReadLimit: 50000,
	HTTPClient:        hc,
	RequestHeaders: http.Header{
		"X-Trace-Id": {"audit-123"},
	},
})
if err != nil {
	// hard failure: invalid Options.Address, unreachable CP, or a non-Kuma endpoint
}
out, err := rep.RenderJSON() // or rep.RenderHTML()
```

`preflight.Audit` performs no I/O beyond requests to `Options.Address` — it never prints,
logs, or calls `os.Exit`. That is why `Options.LatestPatch` is an input: the CLI reads the
`kumahq/kuma` GitHub releases API for it, and an importer must supply the value the same way
(hardcoded, from its own cache, or from that API) to get a conclusive report. See the
[`preflight`](preflight) package doc for the full API, including
`preflight.UpgradeTargetMinor` for the 2.x minor the check is scoped to and
`preflight.RemovedKinds()` for introspecting the removed-resource catalog.
Importers can also supply a custom `HTTPClient` and static `RequestHeaders` for control-plane
requests; built-in defaults fill only missing headers, and `Token` still overrides any custom
`Authorization` header.
`Options.ResourceReadLimit` bounds how many resource items one audit admits across all
collection reads; when the ceiling is reached the affected collection becomes a coverage gap,
the report is inconclusive, and later collection reads stop. Set it to `0` to leave reads
unlimited.

Set `Options.SkipAuditedControlPlaneVersionCheck` to exclude only the audited control plane's
own patch level from the version-currency check — connected zone control planes are still
checked, and the report records an info finding noting the exclusion so its absence is never
read as a pass.

The report types are also re-exported as aliases from
[`reportmodel`](reportmodel) (which additionally owns the `--classify`
`Classification` contract), so code written against that import path still compiles.
Both contracts are published as JSON Schema in [`docs/openapi.yaml`](docs/openapi.yaml).

## More

- **[Full flag reference + the checks it runs](cmd/kuma3-preflight/README.md)**
- [`docs/deprecated-features.md`](docs/deprecated-features.md) — the 3.0 deprecations every check tracks
- [`docs/test-setup.md`](docs/test-setup.md) — spin up a local k3d or Universal CP to try it against
- The same binary can also classify a Kuma **e2e test suite** by its 3.0-removed-feature
  usage — see [`docs/e2e-classification.md`](docs/e2e-classification.md).
