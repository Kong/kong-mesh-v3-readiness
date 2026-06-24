# Universal e2e — Kuma 3.0 rework report

Source data: `kuma3-preflight --classify` over `test/e2e_env/universal`, combining a static
source scan with **251 per-spec snapshots** captured during a full `make test/e2e-universal`
run (250/252 specs passed; 1 `[ipv6-not-supported]` env-only failure). See
[`e2e-classification.md`](e2e-classification.md) for the method.

## Status (kumahq/kuma)

Tracked by umbrella **#17001** with workstream subissues **#17002–#17007**. **PR #16998
(merged)** already removed the universal old-policy *subject* specs (`trafficpermission,
trafficroute, trafficlog, retry, ratelimit, proxytemplate, virtualoutbound, matching`, old
`healthcheck`, `observability` TrafficTrace), keeping the `Mesh*` siblings
(`timeout/meshtimeout.go`, `observability/meshtrace.go` + metrics). So **WS1 is done except
`externalservices/`**, and **WS2 is reduced to gap verification** (behavioral
MeshHTTPRoute/MeshTCPRoute routing + VirtualOutbound→MeshService). WS3–WS6 are unaffected. The
tables below reflect the **pre-merge** tree.

## Why

Kuma 3.0 removes a set of resources, Mesh fields, Dataplane fields and CP settings. The
universal e2e suite still exercises many of them — some as the **test's subject** (the test
only exists to cover a removed resource) and some as **incidental scaffolding** (a removed
construct used to set up a test about something else). Both must change before the suite can
run on 3.0. This report classifies the usage and proposes a 6-workstream rework.

## What the data shows (three buckets)

**A. Genuinely test-authored deprecated usage — the actionable signal.** Removed resources,
inline Mesh fields, and deprecated fields inside the *new* `Mesh*` policies. See the
per-kind → test-dir table in the appendix.

**B. CP/framework default-policy noise.** `mesh-{timeout,circuit-breaker,retry}-all-<mesh>`
default policies are auto-created on ~every mesh and use deprecated `to: Mesh` / `from` /
`proxyTypes`. One framework/CP-default fix, not a per-test concern.

**C. Test-CP config.** The e2e CP runs with `deltaXds`, `inboundTagsDisabled`,
`kdsEventBasedWatchdog`, `sidecarContainers` off and meshes on `meshServices.mode != Exclusive`
— i.e. not 3.0-shaped.

**Delete-vs-port pivot:** a legacy policy test can be deleted only if a `Mesh*` test dir
already covers the behavior. Present: `meshtrafficpermission, meshaccesslog, meshratelimit,
meshretry, meshhealthcheck, meshfaultinjection, meshproxypatch, meshexternalservice, meshtls`.
**Missing (must be written first):** `meshhttproute`/`meshtcproute` (← TrafficRoute),
`meshtimeout` (← Timeout), `meshtrace` (← TrafficTrace), `meshmetric` (← inline metrics),
`meshcircuitbreaker` (← CircuitBreaker).

## Workstreams (→ subissues)

Suggested order: **WS6 → WS3 → (WS2, WS4, WS5 in parallel) → WS1**.

### WS1 — Delete legacy policy tests that already have `Mesh*` coverage
Verify the `Mesh*` dir covers the behavior, then delete the legacy test (and its legacy
scaffolding). Dirs: `trafficpermission/`, `trafficlog/`, `ratelimit/`, `retry/`,
`healthcheck/`, `matching/` (FaultInjection), `proxytemplate/`, and the `ExternalService`
parts of `externalservices/`. **Blocked by WS3** (shared mTLS/legacy scaffolding) for dirs
that double as scaffolding.

### WS2 — Port legacy tests to the MISSING `Mesh*` coverage, then delete the legacy test
Write the new test dir, confirm parity, delete the legacy one:
- `trafficroute/` → new `meshhttproute/` + `meshtcproute/`
- `timeout/` → new `meshtimeout/`
- `observability/` TrafficTrace → new `meshtrace/`
- `observability/` inline metrics → new `meshmetric/` (coordinate with WS3)
- `CircuitBreaker` scaffolding → new `meshcircuitbreaker/`
- `virtualoutbound/` → unified naming + MeshService hostnames (no policy replacement; rework or drop)

### WS3 — Replace inline Mesh-object settings (scaffolding) with the 3.0 model
- **Inline mTLS on Mesh → MeshIdentity + MeshTrust** — 16 dirs (`mtls, externalservices,
  gateway, healthcheck, meshservice, envoyconfig, strictinbounds, transparentproxy,
  observability, zoneegress, meshaccesslog, meshexternalservice, meshhealthcheck, meshtls,
  meshtrafficpermission, trafficpermission`). Best done as a shared framework helper change.
- Inline `metrics` → MeshMetric (`observability`); `tracing` → MeshTrace (`observability`);
  `logging` → MeshAccessLog (`trafficlog`).
- `networking.outbound.passthrough` → MeshPassthrough (`externalservices, meshexternalservice`).
- `routing.zoneEgress` → removed (`externalservices, zoneegress`).
- `constraints` → removed; rework `membership/`.

### WS4 — Fix deprecated fields inside the new `Mesh*` policy specs
The 3.0 policies themselves are written with removed syntax:
- `from:` → `rules:` (MeshTrafficPermission, MeshFaultInjection, MeshTimeout, MeshTLS, MeshAccessLog)
- `to[].targetRef.kind`: subset/selector kinds (`MeshSubset`, `MeshServiceSubset`) and
  `MeshGateway` removed — `Mesh` (all outbound) stays valid and is NOT a migration
  (MeshCircuitBreaker, MeshRetry, MeshTimeout, MeshHTTPRoute, MeshAccessLog,
  MeshRateLimit, MeshFaultInjection, MeshLoadBalancingStrategy)
- `targetRef.proxyTypes` removed (`envoyconfig`, `gateway`)
- top-level `targetRef.kind: MeshSubset` removed (MeshTLS, MeshTrafficPermission)
- MeshHealthCheck `healthyPanicThreshold` → MeshCircuitBreaker (`meshhealthcheck/`)
- MeshTrace OTel `endpoint` → `backendRef` (`envoyconfig-zoneproxies`)
- MeshLoadBalancingStrategy `hashPolicies` relocation + `SourceIP` type (`mesh-load-balancing-strategy/`)

### WS5 — Dataplane & gateway model
- Builtin gateway (`MeshGateway` + Dataplane `networking.gateway`) → delegated gateway:
  `gateway/`, `gateway-resources`, cross-mesh, `envoyconfig-builtingateway`, `meshaccesslog`, `meshtrace`.
- `reachableServices` → `reachableBackends`: `reachableservices/`.
- Per-proxy Dataplane `metrics` override → MeshMetric: `observability` (applications-metrics).
- Universal Dataplane `spec.probes` → app-probe-proxy (audit which dirs set probes).

### WS6 — Framework defaults & 3.0-shaped test CP (buckets B + C)
- Stop generating deprecated-shaped default policies `mesh-{timeout,circuit-breaker,retry}-all-<mesh>`.
- Run the universal CP 3.0-shaped: enable `deltaXds`, `inboundTagsDisabled`,
  `kdsEventBasedWatchdog`, `sidecarContainers`; default test meshes to `meshServices.mode: Exclusive`.
  This surfaces real regressions the current config hides.

## Reproduce

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight     # in v3-readiness
# static only:
./bin/kuma3-preflight --classify --source-dir ~/kong/kuma/test/e2e_env/universal --format markdown
# + dynamic (capture during an e2e run — see docs/e2e-classification.md):
./bin/kuma3-preflight --classify \
  --source-dir ~/kong/kuma/test/e2e_env/universal \
  --reports-dir ~/kong/kuma/preflight-out --format html --output classification.html
```

## Appendix — legacy resource → test dirs (static scan)

| Removed resource | Test dirs |
|---|---|
| TrafficRoute | externalservices, gateway, healthcheck, observability, proxytemplate, ratelimit, retry, timeout, trafficlog, trafficpermission, trafficroute |
| TrafficPermission | externalservices, gateway, healthcheck, mtls, observability, proxytemplate, ratelimit, retry, trafficlog, trafficpermission, trafficroute |
| Timeout | healthcheck, proxytemplate, timeout, trafficlog |
| RateLimit | gateway, ratelimit, zoneegress |
| Retry | healthcheck, proxytemplate, ratelimit, retry, trafficlog |
| CircuitBreaker | healthcheck, proxytemplate, trafficlog |
| HealthCheck | healthcheck |
| FaultInjection | matching, retry, zoneegress |
| TrafficLog | trafficlog |
| TrafficTrace | observability |
| ProxyTemplate | gateway, proxytemplate |
| VirtualOutbound | virtualoutbound |
| ExternalService | externalservices, gateway, meshaccesslog, ratelimit, trafficroute, zoneegress |
| MeshGateway (builtin) | envoyconfig, gateway |

Inline Mesh/Dataplane fields → dirs: mtls (16 dirs, see WS3), metrics/tracing (observability),
logging (trafficlog), passthrough (externalservices, meshexternalservice), routing.zoneEgress
(externalservices, zoneegress), constraints (membership), Dataplane.gateway (gateway),
proxyTypes (envoyconfig, gateway).
