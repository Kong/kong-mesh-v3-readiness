# Kuma — Deprecated / Replaced Features

Reference list of features deprecated, replaced, or slated for removal. Used as input for follow-up tasks.

## Core architecture shifts (your list — confirmed)

| Feature | Old | New / Target | Notes |
|---|---|---|---|
| **MeshService mode** | `meshServices.mode: Disabled` (default) | `Exclusive` (target default) | Migration path `Disabled → Everywhere → Exclusive`. Exclusive disables legacy `kuma.io/service` tag routing, stops legacy ServiceInsight computation, gates Zone Proxy + MeshIdentity. `api/mesh/v1alpha1/mesh.proto`, `mesh_helpers.go` |
| **Unified resource naming** | per-component legacy Envoy resource/stat names | `dataPlane.features.unifiedResourceNaming: true` (KRI-based) | Default `false` today, target `true`. `pkg/config/app/kuma-dp/config.go` |
| **Old (legacy) policies** | `TrafficPermission`, `TrafficRoute`, `TrafficLog`, `TrafficTrace`, `ProxyTemplate` | `MeshTrafficPermission`, `MeshHTTPRoute`/`MeshTCPRoute`, `MeshAccessLog`, `MeshTrace`, `MeshProxyPatch` | targetRef policies supersede selector policies |
| **Other dropped policies** | legacy `OPA`, `MeshGlobalRateLimit` | `MeshOPA` (stays) | enterprise/downstream policies (not in this OSS repo); only the old OPA policy is removed |
| **Policy roles** | producer/consumer policy roles | — | role concept dropped |
| **Shadow policies** | — | kept **internal-only** | can't drop (too much e2e coverage); remove only public docs |
| **Policy direction** | `from[]` arrays | `to[]` / `rules[]` | `from` deprecated across many policies (see below), removal targeted for **3.0** |
| **mTLS config** | `Mesh.spec.mtls` backends | `MeshIdentity` + `MeshTrust` | MeshIdentity provisions identity/certs (Bundled / SPIRE / Extension), auto-generates MeshTrust CA bundles. Requires `meshServices.mode: Exclusive` |
| **Zone proxies** | separate `ZoneIngress` + `ZoneEgress` resources | unified **Zone Proxy** (Listener types embedded in Dataplane) | `ZoneIngress`/`ZoneEgress` listener types in `dataplane.proto`. Functions only in Exclusive mode; egress needs WorkloadIdentity |
| **MeshTrafficPermission matching** | `from[].targetRef` (MeshService/MeshSubset) | `rules[]` with `matches[].spiffeID` (Exact/Prefix) + SNI match | Requires MeshIdentity. `from` deprecated, removed in 3.0 |
| **Gateways (ALL types)** | `MeshGateway`, `MeshGatewayInstance`, `MeshGatewayRoute`, builtin gateway, Gateway API / GAMMA support | delegated gateway (Kong/third-party) only | 3.0 drops Kuma's gateway business entirely — not just builtin. See Gateway section below |
| **Reachable services** | `kuma.io/transparent-proxying-reachable-services` / `reachableServices` (kuma.io/service based) | `reachableBackends` (MeshService based) | Tied to Exclusive mode + MeshService migration |
| **Locality-aware LB** | `Mesh.spec.routing.localityAwareLoadBalancing` (boolean) | **MeshLoadBalancingStrategy** | Boolean superseded by the policy |
| **Inbound tags** | inbound `kuma.io/*` tags generated on dataplane inbounds (default) | run with inbound tags **disabled** | See Experimental config below |
| **Proxy grouping** | `kuma.io/service` tag groups proxies (incl. metrics/traces dimension) | **Workload** resource | Adopt Workload — the new logical grouping of dataplane proxies and the primary grouping key for metrics/traces; pairs with MeshService + inbound-tags-disabled. `pkg/core/resources/apis/workload` |

## Experimental config → becoming default

All flags under `experimental:` (`ExperimentalConfig`, `pkg/config/app/kuma-cp/config.go:465`) are slated to become the default behavior. Env var prefix `KUMA_EXPERIMENTAL_*`.

| Flag (`experimental.*`) | Env var | Current default | Target |
|---|---|---|---|
| `inboundTagsDisabled` | `..._INBOUND_TAGS_DISABLED` | `false` | `true` — CP runs without inbound `kuma.io/*` tags, label-based MeshService selection instead |
| `kubeOutboundsAsVIPs` | `..._KUBE_OUTBOUNDS_AS_VIPS` | `true` (already on) | default — k8s outbounds in ConfigMap next to VIPs instead of embedded in Dataplane |
| `useTagFirstVirtualOutboundModel` | `..._USE_TAG_FIRST_VIRTUAL_OUTBOUND_MODEL` | `false` | `true` — compressed virtual-outbound model (for >2k services) |
| `autoReachableServices` | `..._AUTO_REACHABLE_SERVICES` | `false` | **removed entirely** — flag/feature dropped (CP auto-computed reachable services from MeshTrafficPermission) |
| `sidecarContainers` | `..._SIDECAR_CONTAINERS` | `true` (already on) | default — native k8s sidecar containers |
| `deltaXds` | `..._DELTA_XDS` | `false` | `true` — Delta xDS delivery to sidecars |
| `kdsEventBasedWatchdog.enabled` | `..._KDS_EVENT_BASED_WATCHDOG_ENABLED` | `false` | `true` — event-based KDS snapshot generation |
| `ingressTagFilters` | `..._INGRESS_TAG_FILTERS` | `[]` | tuning knob — trims ZoneIngress tag size (not a boolean default flip) |

## `from` field deprecations (→ use `rules`, removal in 3.0)

All have a `deprecated.go` under `pkg/plugins/policies/<name>/api/v1alpha1/`:

- MeshTrafficPermission — use `rules` with MeshIdentity (spiffeId)
- MeshFaultInjection — `rules` with SPIFFE-based matches
- MeshTLS
- MeshAccessLog
- MeshRateLimit
- MeshCircuitBreaker
- MeshTimeout

## Mesh object settings dropped / replaced

- `Mesh.spec.metrics` (prometheus) → **MeshMetric** (also: metrics pod annotations deprecated)
- `Mesh.spec.tracing` → **MeshTrace**
- `Mesh.spec.logging` → **MeshAccessLog**
- `Mesh.spec.mtls` → **MeshIdentity** + **MeshTrust** (see core table)
- `Mesh.spec.routing.localityAwareLoadBalancing` → **MeshLoadBalancingStrategy** (see core table)
- Passthrough setting (`Mesh.spec.networking.outbound` passthrough) → **MeshPassthrough**
- `Mesh.spec.routing.zoneEgress` boolean (`mesh.proto:289`) → dropped
- `Mesh.spec.routing.defaultForbidMeshExternalServiceAccess` (`mesh.proto:293`) → dropped
- Mesh membership / `Mesh.spec.constraints.dataplaneProxy` (`mesh.proto:62-92`) → dropped

## targetRef kind deprecations

The selector-style kinds are being removed in favor of `Dataplane` + labels **everywhere a targetRef appears** (top-level `targetRef`, `to[].targetRef`, `from[].targetRef`):

- `MeshService`, `MeshServiceSubset`, `MeshSubset` kinds → use **`Dataplane` + labels** (`pkg/plugins/policies/core/.../validator.go`)
- `MeshHTTPRoute` in top-level targetRef → use it in `spec.to[].targetRef`
- MeshTrafficPermission: `MeshService` value in `from[].targetRef.kind` → `MeshSubset` + `kuma.io/service` tag (interim); ultimate target is `rules` + spiffeID
- Net direction: tag/service-subset selectors → label-based `Dataplane` selection backed by MeshService
- **Top-level targetRef** restricted to only `Mesh` and `Dataplane` (all other kinds dropped)
- **`to[].targetRef`** restricted to `Mesh*Service` kinds only (`MeshService` / `MeshExternalService` / `MeshMultiZoneService`)
- **`proxyTypes` in targetRef** (`api/common/v1alpha1/targetref.go:101`) → dropped (Gateway/Sidecar proxy-type filtering)

## Backend / endpoint deprecations

- MeshAccessLog OpenTelemetry `Endpoint` → `BackendRef`
- MeshMetric backend endpoints → `BackendRef`
- MeshTrace OpenTelemetry `Endpoint` → `BackendRef`

## Per-policy field deprecations

- **MeshLoadBalancingStrategy**: `loadBalancer.ringHash.hashPolicies[]` and `loadBalancer.maglev.hashPolicies[]` → `to[].default.hashPolicies[]`; hash policy `SourceIP` type → `Connection`
- **MeshHealthCheck**: `healthyPanicThreshold` → moved to **MeshCircuitBreaker**
- **MeshTrust**: `spec.origin` → `status.origin`
- **Timeout (legacy)**: `timeout.http.grpc.streamIdleTimeout` / `maxStreamDuration` / whole `grpc` section → `timeout.http.*`
- **MeshInsight**: `policyStat` → `resources`

## Resources dropped

- **ExternalService** → **MeshExternalService**
- **ProxyTemplate** → **MeshProxyPatch** (also listed as legacy policy above)
- **VirtualOutbound** → unified naming + MeshService hostnames
- **ServiceInsight** → dropped (already not computed in Exclusive mode)
- **Tags on dataplanes** → dropped (label-based selection + MeshService; broader than inbound tags)

## Gateway — Kuma exits the gateway business

All gateway functionality delegated to Kong / third-party (delegated gateway). Dropped:

- **MeshGateway**, **MeshGatewayInstance**, **MeshGatewayRoute**
- Builtin gateway type
- Gateway API + GAMMA built-in support
- `proxyTypes` in policy targetRef (see targetRef section)
- `networking.gateway` section in Dataplane

## Observability

- Old observability config → only **KRI-based** config (ties to unified naming)
- Metrics via Dataplane annotations → **MeshMetric**
- `install observability` command/feature → dropped; dashboards shipped inside the release `tar.gz`
- ConfigMap reconcilers → dropped
- Virtual probes cleanup (app-probe-proxy path; cf. Dataplane `spec.probes`)

## Infrastructure / deployment

- **Global CP on Kubernetes** → dropped as supported deployment mode
- **Delta xDS** → the only option (SOTW path removed, not just defaulted on)
- **CoreDNS + Envoy DNS filter** → dropped (DNS handling reworked)
- **eBPF** transparent proxy → dropped
- **Old inspect APIs** → dropped (new inspect API only)
- **Pod resources** instead of container resources
- **`KUMA_RUNTIME_KUBERNETES_INJECTOR_BUILTIN_DNS_LOGGING`** (embedded DNS logging) → dropped
- Routing MeshExternalService through a specific zone → dropped

## Naming / identity / misc

- **Legacy `kuma.io/service` tag routing** → MeshService resources + explicit BackendRef (`LegacyOutbound` in `pkg/core/xds/types/outbound.go`)
- **Non-RFC-1035 resource names** deprecated for Mesh, Zone, MeshService, MeshExternalService, MeshMultiZoneService (`deprecated.go` per resource)
- **MeshMultiZoneService**: names > 63 chars deprecated
- **`kuma.io/mesh` annotation** → use label
- **MeshGatewayInstance**: `kuma.io/service` tag → auto-generated `serviceName`
- **Dataplane `spec.probes`** → removed for Universal; not needed on Kubernetes
- **Legacy HMAC256 signing keys** (pre-1.4.x) → asymmetric RSA/ECDSA (`pkg/core/tokens/signing_key_accessor.go`)

