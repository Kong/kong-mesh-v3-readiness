# kuma3-preflight

Audits a running Kuma control plane (zone or global) over its REST API and
produces a self-contained HTML (default) or JSON report of what must change before
upgrading to **Kuma 3.0**. (Markdown is produced by `--classify`, not a CP audit.)

The checks track `docs/deprecated-features.md`.

## Usage

```bash
go run ./cmd/kuma3-preflight --address http://localhost:5681 --output report.html
```

Against a Kubernetes zone CP, port-forward first:

```bash
kubectl -n kuma-system port-forward svc/kuma-control-plane 5681:5681
go run ./cmd/kuma3-preflight --output report.html
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--address` | `http://localhost:5681` | CP REST API base URL |
| `--token` | _(none)_ | Bearer token. Optional, but Kong Mesh gates `GET /config` behind RBAC — without it that endpoint becomes a coverage gap (run is inconclusive, not failed) |
| `--mesh` | _(all)_ | Limit the audit to one mesh |
| `--output` | _(stdout)_ | Write the report to a file |
| `--format` | `html` | CP-audit output: `json` or `html` (Markdown is `--classify`-only). With `--classify`: `markdown` (default), `json`, or `html` |
| `--from-json` | _(none)_ | Render a previously captured JSON report (path, or `-` for stdin) instead of auditing |
| `--timeout` | `60s` | Overall audit timeout |
| `--inspect-dataplanes` | `0` | Fetch up to N dataplanes' Envoy config dumps to detect removed features (`0` = skip; expensive per-proxy fetch) |
| `--latest-version` | _(GitHub lookup)_ | Latest 2.14 patch to check the CP / zones against (e.g. `2.14.7`). When set, skips the `kumahq/kuma` GitHub releases lookup, keeping the run offline and deterministic |
| `--classify` | `false` | Classification mode: instead of auditing a CP, classify e2e tests by their 3.0-deprecated-feature usage (see below). Uses `--source-dir` and/or `--reports-dir` |
| `--source-dir` | _(none)_ | With `--classify`: root of an e2e test tree to scan statically (e.g. a Kuma `test/e2e_env/<env>` dir) |
| `--reports-dir` | _(none)_ | With `--classify`: directory of per-spec preflight JSON snapshots captured during an e2e run, folded into the classification |

Exit codes (so it can gate CI): `0` clean · `1` blockers found · `2` operational error · `3` audit inconclusive (a collection could not be read, or a resource spec failed to parse — the result is not a proven clean bill of health). In `--classify` mode the exit code is `0` on success or `2` on error.

## Classify e2e tests (`--classify`)

A second mode reuses the same deprecation catalog (`legacyMeshScoped` in `audit.go`) to
classify a Kuma **e2e test suite** by which 3.0-removed features each test exercises — so
you can decide which e2e tests to **remove/replace** (the test's subject is a removed
resource) vs **rewrite** (it uses a removed thing only as scaffolding).

```bash
# Static: scan the e2e sources (fast, no CP, per-feature attribution)
./bin/kuma3-preflight --classify --source-dir ~/kuma/test/e2e_env/universal --format markdown

# + Dynamic: fold in per-spec snapshots captured during an e2e run (see docs/e2e-classification.md)
./bin/kuma3-preflight --classify \
  --source-dir ~/kuma/test/e2e_env/universal --reports-dir ./preflight-out \
  --format html --output classification.html
```

Output (markdown/json/html, same one-model contract, JSON schema
`kuma3-preflight-classification/v1`) leads — when any are present — with a **🌐 Global
migrations** table (omitted when there are none): the cross-cutting fixes (a non-removable
field/policy/mesh setting recurring across `globalSuiteThreshold` suites, e.g. inline
`Mesh.mtls`→MeshIdentity+MeshTrust or the shared `MeshTimeout`/`MeshTrafficPermission`
defaults) that are fixed once centrally. Below it,
**📁 Per-suite findings** lists, per suite, only what is *unique* to that suite (its
removed resources and one-off targetRef usages) as a table; suites whose findings are
entirely global collapse into a single trailing line. Each row carries the deprecated kind,
count, source (`static`/`dynamic`), 3.0 replacement, and examples. Emojis are wayfinding
only (one env-status glyph + one icon per section) — tables themselves are emoji-free. The
end-to-end capture workflow is documented in
[`docs/e2e-classification.md`](../../docs/e2e-classification.md).

## Output formats

A CP audit renders **`html`** (default) or **`json`** — both from the same underlying
data, so they never disagree. (Markdown is produced only by `--classify`.)

- **`html`** (default) — a single, self-contained page (inline CSS + JS, no network requests,
  works offline from `file://`): status banner, clickable severity filters, full-text search,
  and a manual-checks checklist whose progress is saved per report in the browser.
- **`json`** — a stable, machine-readable document (`schema`, `status`, `summary`,
  `findings[]`, `coverageGaps[]`, `manualChecks[]`). Status maps to the same exit codes.
  This is the format the e2e capture hook saves per spec and `--classify` folds back in.

```bash
# Capture machine-readable JSON in CI…
./bin/kuma3-preflight --address http://localhost:5681 --format json --output report.json

# …then build the static site from that JSON later, without touching the control plane:
./bin/kuma3-preflight --from-json report.json --format html --output report.html

# (or pipe it)
cat report.json | ./bin/kuma3-preflight --from-json - --format html > report.html
```

## What it checks

- **Removed resources** — TrafficPermission/Route/Log/Trace, FaultInjection,
  HealthCheck, CircuitBreaker, Retry, Timeout, RateLimit, ProxyTemplate,
  VirtualOutbound, ExternalService, MeshGateway, MeshGatewayRoute.
- **Mesh object settings** — inline mTLS, outbound passthrough, `routing.zoneEgress`,
  `defaultForbidMeshExternalServiceAccess`, locality-aware LB, inline metrics/tracing/logging,
  membership `constraints`; flags when `meshServices.mode` is not `Exclusive`.
- **New policies** — `from` usage, top-level `targetRef` kinds other than Mesh/Dataplane,
  `to` targets other than `Mesh*Service`, `proxyTypes`.
- **Per-policy field deprecations** — OpenTelemetry `endpoint` (→ `backendRef`) on
  MeshAccessLog/MeshTrace/MeshMetric; MeshLoadBalancingStrategy `loadBalancer.{ringHash,maglev}.hashPolicies`
  and the `SourceIP` hash type; MeshHealthCheck `healthyPanicThreshold` (→ MeshCircuitBreaker);
  MeshTrust `spec.origin` (→ `status.origin`).
- **Dataplanes** — `reachableServices`, builtin `networking.gateway` section, Universal
  `spec.probes`, and a per-proxy `spec.metrics` override (deprecated → MeshMetric).
- **Dataplane versions** — proxies the CP reports as version-incompatible
  (`kumaCpCompatible: false`), read from `/dataplanes+insights`.
- **Control plane version** — flags a CP (or, on a **global**, any connected zone CP) not on
  the latest 2.14 patch, the only supported 3.0 upgrade source (older patch/minor → blocker).
  The latest patch is looked up from the `kumahq/kuma` GitHub releases at run time (Kong Mesh
  tracks the same patch numbers); pass `--latest-version 2.14.x` to set it explicitly and skip
  the network call (offline/deterministic runs). On a **global** the zone versions come from
  the same `GET /zones+insights` payload — one global audit covers every zone with no extra
  round-trips. If the latest patch can't be determined, or a zone reported no version, it is a
  coverage gap — never a silent pass.
- **Control plane config** (`GET /config`) — global-on-Kubernetes mode, `autoReachableServices`,
  eBPF transparent proxy, unified resource naming, inbound-tags-disabled, delta
  xDS, KDS event-based watchdog, native sidecar containers not yet enabled (all blockers). The
  report's control-plane line shows the CP mode (read from `/config`). Against a **global**
  CP the data-plane-relevant checks run **per zone**, sourced from each zone's config in
  `GET /zones+insights` (examples read `zone <name>: …`); the global keeps only the
  global-on-Kubernetes blocker. A zone that reported no config, or an unreadable/auth-gated
  `/config`/`/zones+insights`, is a coverage gap — never a silent pass.
- **Resource names** — Mesh/MeshService/MeshExternalService/MeshMultiZoneService names that
  are not valid RFC-1035 DNS labels.
- **Zone proxies** — informational count of ZoneIngress/ZoneEgress.
- **Envoy config (opt-in, `--inspect-dataplanes N`)** — fetches up to N proxies' config
  dumps and flags use of the legacy Envoy DNS filter.

It also lists **manual checks** for the remaining 3.0 drops that aren't observable
through the CP API (Gateway API/GAMMA migration, observability install command, CoreDNS,
old inspect-API clients, pod-vs-container resources, Workload adoption, HMAC256 signing-key
rotation, `kuma.io/mesh` annotation→label).
