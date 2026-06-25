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

## More

- **[Full flag reference + the checks it runs](cmd/kuma3-preflight/README.md)**
- [`docs/deprecated-features.md`](docs/deprecated-features.md) — the 3.0 deprecations every check tracks
- [`docs/test-setup.md`](docs/test-setup.md) — spin up a local k3d or Universal CP to try it against
- The same binary can also classify a Kuma **e2e test suite** by its 3.0-removed-feature
  usage — see [`docs/e2e-classification.md`](docs/e2e-classification.md).
