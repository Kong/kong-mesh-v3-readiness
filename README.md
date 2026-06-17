# v3-readiness

Tooling and manual-test material for auditing a running **Kuma 2.x** control plane for
**Kuma 3.0** upgrade readiness.

## Contents

- **[`cmd/kuma3-preflight`](cmd/kuma3-preflight/)** — a stdlib-only Go CLI that audits a
  CP over its REST API and prints a Markdown pre-upgrade report (blockers / warnings /
  manual checks). See its [README](cmd/kuma3-preflight/README.md) for checks and flags.
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
```

The tool is **stdlib-only** (no external dependencies).
