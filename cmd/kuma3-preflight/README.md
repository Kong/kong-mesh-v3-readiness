# kuma3-preflight

Audits a running Kuma control plane (zone or global) over its REST API and
produces a Markdown report of what must change before upgrading to **Kuma 3.0**.

The checks track `docs/deprecated-features.md`.

## Usage

```bash
go run ./cmd/kuma3-preflight --address http://localhost:5681 > report.md
```

Against a Kubernetes zone CP, port-forward first:

```bash
kubectl -n kuma-system port-forward svc/kuma-control-plane 5681:5681
go run ./cmd/kuma3-preflight --output report.md
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--address` | `http://localhost:5681` | CP REST API base URL |
| `--token` | _(none)_ | Bearer token, if the API requires auth |
| `--mesh` | _(all)_ | Limit the audit to one mesh |
| `--output` | _(stdout)_ | Write the report to a file |
| `--timeout` | `60s` | Overall audit timeout |

Exit codes (so it can gate CI): `0` clean · `1` blockers found · `2` operational error · `3` audit inconclusive (a collection could not be read, or a resource spec failed to parse — the result is not a proven clean bill of health).

## What it checks

- **Removed resources** — TrafficPermission/Route/Log/Trace, FaultInjection,
  HealthCheck, CircuitBreaker, Retry, Timeout, RateLimit, ProxyTemplate,
  VirtualOutbound, ExternalService, MeshGateway, MeshGatewayRoute.
- **Mesh object settings** — inline mTLS, outbound passthrough, `routing.zoneEgress`,
  `defaultForbidMeshExternalServiceAccess`, locality-aware LB, inline metrics/tracing/logging,
  membership `constraints`; warns when `meshServices.mode` is not `Exclusive`.
- **New policies** — `from` usage, top-level `targetRef` kinds other than Mesh/Dataplane,
  `to` targets other than `Mesh*Service`, `proxyTypes`.
- **Per-policy field deprecations** — OpenTelemetry `endpoint` (→ `backendRef`) on
  MeshAccessLog/MeshTrace/MeshMetric; MeshLoadBalancingStrategy `loadBalancer.{ringHash,maglev}.hashPolicies`
  and the `SourceIP` hash type; MeshHealthCheck `healthyPanicThreshold` (→ MeshCircuitBreaker);
  MeshTrust `spec.origin` (→ `status.origin`).
- **Dataplanes** — `reachableServices`, builtin `networking.gateway` section, Universal
  `spec.probes`.
- **Resource names** — Mesh/MeshService/MeshExternalService/MeshMultiZoneService names that
  are not valid RFC-1035 DNS labels.
- **Zone proxies** — informational count of ZoneIngress/ZoneEgress.

It also lists **manual checks** for config/runtime-level drops that can't be seen
through CP resources (unified naming, inbound-tags-disabled, experimental flag
defaults, DNS/eBPF, observability install, etc.).
