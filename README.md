# v3-readiness

Tooling and manual-test material for auditing a running **Kuma 2.x** control plane for
**Kuma 3.0** upgrade readiness.

## Contents

- **[`cmd/kuma3-preflight`](cmd/kuma3-preflight/)** — a stdlib-only Go CLI that audits a
  CP over its REST API and emits a pre-upgrade report (blockers / warnings / manual checks)
  as Markdown (default), JSON, or a self-contained HTML page. See its
  [README](cmd/kuma3-preflight/README.md) for checks, flags, and output formats.
- **[`examples/`](examples/)** — real reports captured against live Kubernetes and
  Universal control planes, so you can see the output without running anything.
- **[`docs/`](docs/)**
  - [`deprecated-features.md`](docs/deprecated-features.md) — source of truth for 3.0
    deprecations/removals every check tracks.
  - [`test-plan.md`](docs/test-plan.md) — manual test plan (TC-1…TC-27 + smoke tests).
  - [`test-setup.md`](docs/test-setup.md) — reproducible Kubernetes (k3d) **and** Universal
    CP environments + fixtures.
  - [`test-results.md`](docs/test-results.md) — executed results, including real-CP runs.

## Quick start

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight

# Point at a CP (port-forward a k8s zone CP, or run a local universal CP — see docs/test-setup.md)
./bin/kuma3-preflight --address http://localhost:5681 --output report.md
echo "exit=$?"   # 0 clean · 1 blockers · 2 operational error · 3 inconclusive

# Or emit JSON / a self-contained HTML page instead of Markdown:
./bin/kuma3-preflight --address http://localhost:5681 --format json --output report.json
./bin/kuma3-preflight --from-json report.json --format html --output report.html
```

Point it at **either a zone or the global** CP. Against a global it covers the whole
multizone estate from one run: resources/policies are global already (KDS sync), and each
zone's control-plane settings are read from `GET /zones+insights` (the zone ships its config
over KDS), so per-zone config findings read `zone <name>: …`.

`--token` is optional, but Kong Mesh gates `GET /config` behind RBAC — without a valid token
that endpoint is skipped as a coverage gap (the run is **inconclusive**, exit 3, not a hard
failure), so pass `--token` to audit control-plane settings.

The tool is **stdlib-only** (no external dependencies).
