# Kuma — Deprecated / Replaced Features

Reference list of features deprecated, replaced, or slated for removal. Used as input for follow-up tasks.

## Core architecture shifts (your list — confirmed)

| Feature | Old | New / Target | Notes |
|---|---|---|---|
| **MeshService mode** | `meshServices.mode: Disabled` (default) | `Exclusive` (target default) | Migration path `Disabled → Everywhere → Exclusive`. Exclusive disables legacy `kuma.io/service` tag routing, stops legacy ServiceInsight computation, gates Zone Proxy + MeshIdentity. `api/mesh/v1alpha1/mesh.proto`, `mesh_helpers.go` |
| **Unified resource naming** | per-component legacy Envoy resource/stat names | `dataPlane.features.unifiedResourceNaming: true` (KRI-based) | Default `false` today, target `true`. `pkg/config/app/kuma-dp/config.go` |
| **Old (legacy) policies** | `TrafficPermission`, `TrafficRoute`, `TrafficLog`, `TrafficTrace`, `ProxyTemplate` | `MeshTrafficPermission`, `MeshHTTPRoute`/`MeshTCPRoute`, `MeshAccessLog`, `MeshTrace`, `MeshProxyPatch` | targetRef policies supersede selector policies |
| **Other dropped policies** | legacy `OPA`, **`MeshGlobalRateLimit`** | `MeshOPA` (stays); global rate limiting dropped (no replacement) | Enterprise (Kong Mesh) policies. Both the legacy `OPA` policy and `MeshGlobalRateLimit` are removed in 3.0. Preflight flags any `MeshGlobalRateLimit` instance as a blocker (`checkRemovedEnterprisePolicies`); enterprise-only, so a 404 on OSS Kuma is "not served", not a coverage gap |
| **Policy roles** | producer/consumer policy roles | — | role concept dropped |
| **Shadow policies** | — | kept **internal-only** | can't drop (too much e2e coverage); remove only public docs |
| **Policy direction** | `from[]` arrays | `to[]` / `rules[]` | `from` deprecated across many policies (see below), removal targeted for **3.0** |
| **mTLS config** | `Mesh.spec.mtls` backends | `MeshIdentity` + `MeshTrust` | MeshIdentity provisions identity/certs (Bundled / SPIRE / Extension), auto-generates MeshTrust CA bundles. Requires `meshServices.mode: Exclusive` |
| **Zone proxies** | separate `ZoneIngress` + `ZoneEgress` resources | unified **Zone Proxy** (Listener types embedded in Dataplane) | `ZoneIngress`/`ZoneEgress` listener types in `dataplane.proto`. Functions only in Exclusive mode; egress needs WorkloadIdentity. Cross-zone `MeshService` traffic to a zone is down until a **MeshZoneAddress** advertises that zone's address; 2.14 already ships the resource, so create it before upgrading. Preflight requires one per zone that terminates cross-zone traffic |
| **MeshTrafficPermission matching** | `from[].targetRef` (MeshService/MeshSubset) | `rules[]` with `matches[].spiffeID` (Exact/Prefix) + SNI match | Requires MeshIdentity. `from` deprecated, removed in 3.0 |
| **Gateways (ALL types)** | `MeshGateway`, `MeshGatewayInstance`, `MeshGatewayRoute`, builtin gateway, Gateway API / GAMMA support | delegated gateway (Kong/third-party) only | 3.0 drops Kuma's gateway business entirely — not just builtin. See Gateway section below |
| **Reachable services** | `kuma.io/transparent-proxying-reachable-services` / `reachableServices` (kuma.io/service based) | `reachableBackends` (MeshService based) | Tied to Exclusive mode + MeshService migration |
| **reachableBackends name refs** | `reachableBackends.refs[].name`/`namespace` (Dataplane + `kuma.io/reachable-backends` annotation) | `refs[].labels` (`kuma.io/display-name`, plus `k8s.kuma.io/namespace` and `kuma.io/zone` to keep a `MeshService` name ref scoped to the proxy's own namespace and zone) | kumahq/kuma#18832. Refs without labels resolve to nothing (no outbounds, even with allow-all) and the k8s pod converter rejects the annotation. Preflight flags any ref without `labels` (k8s + Universal) |
| **Locality-aware LB** | `Mesh.spec.routing.localityAwareLoadBalancing` (boolean) | **MeshLoadBalancingStrategy** | Boolean superseded by the policy |
| **Inbound tags** | inbound `kuma.io/*` tags generated on dataplane inbounds (default) | run with inbound tags **disabled** | See Experimental config below |
| **Proxy grouping** | `kuma.io/service` tag groups proxies (incl. metrics/traces dimension) | **Workload** resource | Adopt Workload — the new logical grouping of dataplane proxies and the primary grouping key for metrics/traces; pairs with MeshService + inbound-tags-disabled. `pkg/core/resources/apis/workload`. The kuma.io/workload label is generated from `runtime.kubernetes.workloadLabels` (prioritized pod-label list; empty → pod ServiceAccount name) on k8s, or set directly on the Dataplane on Universal (where the workload generator reads it). Preflight auto-detects readiness: blocker for a Universal Dataplane missing the label. |

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

The selector-style kinds are being removed in favor of `Dataplane` + labels for **policy
selection** (top-level `targetRef` and `from[].targetRef`). This does NOT blanket-remove
every kind from `to[].targetRef` (the destination), which keeps `Mesh` / `Mesh*Service` /
`MeshHTTPRoute` — see the `to[].targetRef` bullet below:

- `MeshServiceSubset`, `MeshSubset` selector kinds → use **`Dataplane` + labels** (`pkg/plugins/policies/core/.../validator.go`); `MeshService` as a *selector* (top-level / `from[]`) likewise moves to labels, but `MeshService` stays valid as a `to[]` destination
- `MeshHTTPRoute` in top-level targetRef → use it in `spec.to[].targetRef`
- MeshTrafficPermission: `MeshService` value in `from[].targetRef.kind` → `MeshSubset` + `kuma.io/service` tag (interim); ultimate target is `rules` + spiffeID
- Net direction: tag/service-subset selectors → label-based `Dataplane` selection backed by MeshService
- **Top-level targetRef** restricted to only `Mesh` and `Dataplane` (all other kinds dropped)
- **`to[].targetRef`** drops the subset/selector kinds (`MeshSubset`, `MeshServiceSubset`) and `MeshGateway`; `Mesh` (all outbound — also the only kind allowed for MeshGateway-targeted policies), the `Mesh*Service` kinds (`MeshService` / `MeshExternalService` / `MeshMultiZoneService`) and `MeshHTTPRoute` stay valid
- **`proxyTypes` in targetRef** (`api/common/v1alpha1/targetref.go:101`) → dropped (Gateway/Sidecar proxy-type filtering)
- **`name` / `namespace` / `mesh` in targetRef and route backendRef** → dropped, selection is by `labels` only (kumahq/kuma#17761, #17756, #17740). A stored name-only ref loses the name: top-level `kind: Dataplane` widens to every Dataplane in the mesh, a `to[]` targetRef or backendRef resolves to nothing. Map `name` → `kuma.io/display-name`, `namespace` → `k8s.kuma.io/namespace`
- **Route `backendRefs`** (MeshHTTPRoute/MeshTCPRoute, incl. RequestMirror) accept only MeshService/MeshExternalService/MeshMultiZoneService (kumahq/kuma#18391); a stored `MeshServiceSubset` ref is unresolved and the rule loses its destination
- **MeshPassthrough non-wildcard `Domain` match** needs `port` (kumahq/kuma#18658); a stored match without one stops applying, and as the only match rejects all passthrough
- **MeshService**: `selector.dataplaneTags` dropped on read (matches 0 proxies, kumahq/kuma#17749), Universal generated MeshServices keyed per `kuma.io/workload` instead of `kuma.io/service`, `identities[].type: ServiceTag` rejected (kumahq/kuma#17973), `ports[].appProtocol` limited to tcp/http/http2/grpc (Kafka removed, kumahq/kuma#17831; MeshMultiZoneService too)
- **MeshExternalService** `tls.verification.caCert`/`clientCert`/`clientKey` move to the typed `SecureDataSource` (kumahq/kuma#17899); a stored old-shape resource is dropped from xDS. 2.14.6+ accepts both shapes (kumahq/kuma#18867), so rewrite before upgrading

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
- **MeshLoadBalancingStrategy**: `localityAwareness.crossZone` is accepted only when `to[].targetRef.kind` is `MeshMultiZoneService` (`meshloadbalancingstrategy/api/v1alpha1/validator.go`)
- **MeshHTTPRoute**: a request matching no rule of an applicable route now returns `404` instead of falling through to the destination. A route written only to anchor a MeshTimeout/MeshRetry/MeshAccessLog silently changes traffic; preflight surfaces routes with no catch-all rule as **info** (a heuristic — the narrowing may well be intended — so it must not gate CI)

## Resources dropped

- **ExternalService** → **MeshExternalService**
- **ProxyTemplate** → **MeshProxyPatch** (also listed as legacy policy above)
- **VirtualOutbound** → unified naming + MeshService hostnames
- **ServiceInsight** → dropped (already not computed in Exclusive mode)
- **Tags on dataplanes** → dropped (label-based selection + MeshService; broader than inbound tags)

### Dataplane `networking` fields (Universal, hand-written)

Reserved or re-validated in `api/mesh/v1alpha1/dataplane.proto`; a 3.0 CP rejects or ignores them. On Kubernetes the CP
generates the Dataplane and a 3.0 CP regenerates it, so preflight flags these only for non-Kubernetes proxies
(`directAccessServices` excepted — it is honored on both).

| Field | 3.0 behavior | Replacement |
|---|---|---|
| `networking.advertisedAddress` | proto field reserved | advertise through the zone proxy config |
| `networking.inbound[].tags` | proto field reserved | Dataplane labels + MeshService selection (pairs with `experimental.inboundTagsDisabled: true`) |
| `networking.outbound[]` without `backendRef` | rejected on write, NACKed over KDS (`dataplane_validator.go`) | `backendRef` to a MeshService / MeshExternalService / MeshMultiZoneService |
| `networking.transparentProxying.directAccessServices` | only `*` is honored; named services silently ignored (`direct_access_proxy_generator.go`) | `*`, or drop direct access |
| `networking.transparentProxying.reachableServices` | removed | `reachableBackends` (see core table) |

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
- **Universal Helm loopback admin** → the chart sets `KUMA_API_SERVER_AUTHN_LOCALHOST_IS_ADMIN=false` in 3.0 (2.x left the built-in default `true`). `kubectl exec`/`port-forward` + kumactl without a token stops working, and the bootstrap admin token can only be read over loopback *before* the upgrade. Not observable from the API — manual check

## Naming / identity / misc

- **Legacy `kuma.io/service` tag routing** → MeshService resources + explicit BackendRef (`LegacyOutbound` in `pkg/core/xds/types/outbound.go`)
- **Non-RFC-1035 resource names** deprecated for Mesh, Zone, MeshService, MeshExternalService, MeshMultiZoneService (`deprecated.go` per resource). For **Zone** it is stricter than a deprecation: a 3.0 zone CP refuses to start on a non-label name (`pkg/config/multizone/multicluster.go`) and the global rejects it on connect (`pkg/core/resources/apis/system/zone_validator.go`), while the Helm chart still accepts dots — so `eu.west` passes `helm upgrade` and then crash-loops. Preflight reads `/zones` on a global, falling back to `multizone.zone.name` in `/config` on a directly audited zone CP
- **MeshMultiZoneService**: names > 63 chars deprecated
- **`kuma.io/mesh` annotation** → use label
- **MeshGatewayInstance**: `kuma.io/service` tag → auto-generated `serviceName`
- **Dataplane `spec.probes`** and virtual probes → removed (kumahq/kuma#17901). On Universal drop the field; on Kubernetes `spec.probes` marks a pod with virtual probes enabled; when Application Probe Proxy is off for it (`kuma.io/application-probe-proxy-port: "0"`) its rewritten kubelet probes fail on 3.0 until re-injected, so move it to Application Probe Proxy first. The Dataplane alone cannot tell the two apart, so every such pod is flagged
- **`kuma.io/protocol` inbound tag** no longer sets the protocol (kumahq/kuma#17861): a Universal inbound without `networking.inbound[].protocol` is served as plain TCP and loses its L7 filters. Inbound `protocol: kafka` is rejected (kumahq/kuma#17831)
- **Unix-socket readiness** removed (kumahq/kuma#18637): a kuma-dp older than 2.14 advertising `feature-readiness-unix-socket` never reports ready against a 3.0 CP
- **`kuma.io/gateway`** moved from Pod annotation to Dataplane **label**, and the value is now a boolean: only `"true"` marks a delegated gateway (`mesh_proto.IsDelegatedGateway`). The 2.x annotation value `enabled` carried over as a label silently stops marking the proxy
- **`k8s.kuma.io/service-account`** is control-plane-owned in 3.0: the admission webhook rejects a user-applied resource carrying it (unless the caller is the CP or in `runtime.kubernetes.allowedUsers`) and xDS auth refuses a proxy whose label does not match its Pod's ServiceAccount. Preflight flags it on Universal Dataplanes (where it has no source at all); the GitOps-on-Kubernetes case is a manual check, since a CP-created Dataplane legitimately carries it
- **`kuma.io/tags` Pod annotation** → no reader in 3.0 (`pkg/plugins/runtime/k8s/metadata/annotations.go`); it is ignored rather than warned about. Manual check
- **Legacy HMAC256 signing keys** (pre-1.4.x) → asymmetric RSA/ECDSA (`pkg/core/tokens/signing_key_accessor.go`)

