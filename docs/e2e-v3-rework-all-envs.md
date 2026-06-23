# e2e v3 rework — all environments (universal + kubernetes + multizone)

Extends [`e2e-v3-rework.md`](e2e-v3-rework.md) (universal) with the kubernetes and multizone
suites. Each was run with the `kuma3-preflight` capture hook and classified.

> All three captures were taken on a **pre-#16998** local checkout, so removed legacy dirs
> still appear (k8s: TrafficLog/VirtualOutbound/Tracing; multizone: TrafficPermission/
> TrafficRoute/VirtualOutbound were removed by #16998). Treat those as already handled.

## Runs

| Env | Specs | Snapshots | Capture target | Notes |
|---|---|---|---|---|
| universal | 250/252 | 251 | the (single) CP | 1 fail = ipv6-not-supported |
| kubernetes | 158/163 | 163 | port-forwarded CP | 5 env flakes (KIC DNS, cross-mesh mTLS, Spire, URLRewrite teardown, Eviction) |
| multizone | 295/297 | 297 | **global CP** | per-zone config fanned out via `/zones+insights`; 2 env flakes |

Artifacts per env in `~/kong/kuma/preflight-out{,-k8s,-mz}/`: 251/163/297 snapshots +
`classification.{md,json}` + `analysis-summary.md`.

## The shared backbone (all three environments)

This is the bulk of the work and is **identical across envs** — fix once (mostly via framework
helpers) and all three benefit:

- **Inline mTLS on Mesh → MeshIdentity + MeshTrust** — universal 16 / k8s 18 / multizone 41
  meshes. The single biggest item.
- **MeshTrafficPermission `from` → `rules`** — all three (U/K/M).
- **Builtin gateway**: `MeshGateway` + Dataplane `networking.gateway` + `MeshHTTPRoute
  targetRef.kind=MeshGateway` → delegated gateway — all three.
- **`reachableServices` → `reachableBackends`** — all three.
- **MeshHealthCheck `healthyPanicThreshold` → MeshCircuitBreaker** — all three.
- **Mesh `passthrough` → MeshPassthrough**, **`routing.zoneEgress`** removed — all three.
- **Removed resources** still referenced everywhere: ExternalService, MeshGateway, Timeout,
  TrafficPermission, TrafficRoute, VirtualOutbound.
- **CP config (bucket C)**: `deltaXds`, `inboundTagsDisabled`, `kdsEventBasedWatchdog` off and
  `meshServices.mode != Exclusive` — all three.

## Kubernetes-specific (what's different there)

- **`unifiedResourceNamingEnabled` off** (injector flag — k8s-only by nature; absent on
  universal which has no injector). 3.0 assumes it on.
- **`MeshGatewayRoute` (removed)** — builtin gateway routes (KIC / gateway tests).
- **Pod-annotation Dataplane metrics** (`prometheus.metrics.kuma.io/*` → per-proxy
  `Dataplane.spec.metrics`) → MeshMetric.
- **MeshPassthrough / MeshProxyPatch / MeshMetric** specs using `proxyTypes`, top-level
  `targetRef.kind=MeshSubset/MeshService`, and MeshMetric OTel `endpoint`.
- **`defaultForbidMeshExternalServiceAccess` on Mesh** (removed).
- Env: KIC (Kong Ingress Controller) and CNI/eBPF paths exercised here, not in universal.

## Multizone-specific (what's different there)

- **Per-zone CP config** — captured once on the global, fanned out via `/zones+insights`:
  k8s zone (`kuma-2`) reports `unifiedResourceNamingEnabled=false`; universal zones
  (`autogenerate-universal`, …) report `deltaXds/inboundTags/kdsEventBasedWatchdog` off. WS6
  must flip these **per zone**, not just on the global.
- **`localityAwareLoadBalancing` on Mesh (removed)** → MeshLoadBalancingStrategy — only here
  (cross-zone LB).
- **Non-RFC-1035 `MeshService` names** — KDS-synced MeshService names aren't valid DNS-1035
  labels; deprecated in 3.0. Only surfaces in multizone (synced naming).
- `MeshGatewayRoute`, `MeshTCPRoute`, and routing-targeted `MeshTimeout/MeshRetry`
  (`targetRef.kind=MeshHTTPRoute`).

## Cross-env matrix (test-authored, default-policy noise excluded)

`U`=universal `K`=kubernetes `M`=multizone. Full matrix is the appendix; highlights:

| Finding | U | K | M |
|---|:-:|:-:|:-:|
| Inline mTLS on Mesh | ✓ | ✓ | ✓ |
| MeshTrafficPermission `from` | ✓ | ✓ | ✓ |
| Builtin gateway (MeshGateway + DP gateway) | ✓ | ✓ | ✓ |
| reachableServices | ✓ | ✓ | ✓ |
| MeshHealthCheck healthyPanicThreshold | ✓ | ✓ | ✓ |
| Unified resource naming off (injector) | · | ✓ | ✓ |
| MeshGatewayRoute (removed) | · | ✓ | ✓ |
| Pod-annotation DP metrics | ✓ | ✓ | · |
| MeshPassthrough proxyTypes | · | ✓ | ✓ |
| localityAwareLoadBalancing on Mesh | · | · | ✓ |
| Non-RFC-1035 MeshService names | · | · | ✓ |

## Implications for the workstreams (umbrella #17001)

The umbrella was universal-scoped. The data shows **WS3 (inline mTLS), WS4 (Mesh\* field
fixes), WS5 (gateway/dataplane), WS6 (CP config)** are **cross-cutting across all three envs** —
they should be done suite-agnostically (framework helpers) rather than per-env. Two additions:

- **WS6** must enable the injector `unifiedResourceNaming` (k8s) and flip config **per zone**
  in multizone (via each zone's CP, since the global only fans the values out).
- New multizone-only item: **rename KDS-synced MeshServices to RFC-1035 labels** (or fix the
  sync naming) — does not exist in universal/k8s.
