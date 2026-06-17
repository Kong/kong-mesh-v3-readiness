# Example reports

Real `kuma3-preflight` output, captured against live 2.x control planes seeded with the
fixtures from [`../docs/test-setup.md`](../docs/test-setup.md). These show exactly what an
operator sees before upgrading to Kuma 3.0.

| File | CP | Scope | Exit |
|---|---|---|---|
| [`kubernetes-all-meshes.md`](kubernetes-all-meshes.md) | k3d (Kubernetes) | all meshes | 1 (blockers) |
| [`kubernetes-mesh-clean.md`](kubernetes-mesh-clean.md) | k3d (Kubernetes) | `--mesh clean` | 1 (blockers) |
| [`universal-all-meshes.md`](universal-all-meshes.md) | Universal (in-memory) | all meshes | 1 (blockers) |
| [`universal-mesh-clean.md`](universal-mesh-clean.md) | Universal (in-memory) | `--mesh clean` | 1 (blockers) |

## How they were produced

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight
bin/kuma3-preflight --address http://localhost:5681 --output examples/<name>.md
```

Each fixture estate has four meshes: `default` (legacy resources + a Dataplane with
`reachableServices`), `legacy` (all inline Mesh settings + `from`/bad-targetRef policies),
`clean` (`meshServices.mode: Exclusive`), and `1badname` (a non-RFC-1035 name).

## Kubernetes vs Universal — the one real difference

Both CPs inline core/Mesh/Dataplane spec the same way, so every spec-level check fires
identically. The difference is in **CP-managed default policies**:

- **Kubernetes** labels its auto-generated defaults (`mesh-timeout-all-<mesh>`, …) with
  `kuma.io/policy-role: system`. The report marks each `(system — CP-managed, update
  before 3.0)` and the header reads `Includes N CP-managed (policy-role: system)
  resource(s)`.
- **Universal** does **not** set that label. The same defaults are still flagged as
  blockers, but **without** the marker and **without** the header line.

This is CP behavior, not a tool difference — the tool reflects the label the CP provides.
The `Dataplane has a probes section` check is also Universal-only (on Kubernetes, probes
are pod-derived and intentionally skipped).
