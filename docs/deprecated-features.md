# Kuma — Deprecated / Replaced Features

Reference list of features deprecated, replaced, or slated for removal. Used as input for follow-up tasks.

## Core architecture shifts (your list — confirmed)

| Feature | Old | New / Target | Notes |
|---|---|---|---|
| **MeshService mode** | `meshServices.mode: Disabled` (default) | `Exclusive` (target default) | Migration path `Disabled → Everywhere → Exclusive`. Exclusive disables legacy `kuma.io/service` tag routing, stops legacy ServiceInsight computation, gates Zone Proxy + MeshIdentity. `api/mesh/v1alpha1/mesh.proto`, `mesh_helpers.go` |
| **Unified resource naming** | per-component legacy Envoy resource/stat names | `dataPlane.features.unifiedResourceNaming: true` (KRI-based) | Default `false` today, target `true`. `pkg/config/app/kuma-dp/config.go` |
| **Old (legacy) policies** | `TrafficPermission`, `TrafficRoute`, `TrafficLog`, `TrafficTrace`, `ProxyTemplate` | `MeshTrafficPermission`, `MeshHTTPRoute`/`MeshTCPRoute`, `MeshAccessLog`, `MeshTrace`, `MeshProxyPatch` | targetRef policies supersede selector policies |
| **Other dropped policies** | legacy `OPAPolicy`, **`MeshGlobalRateLimit`** | `MeshOPA` (stays); global rate limiting dropped (no replacement) | Enterprise (Kong Mesh) policies. Both the legacy `OPAPolicy` (`/meshes/{mesh}/opa-policies`) and `MeshGlobalRateLimit` are removed in 3.0. Preflight flags any instance of either as a blocker (`checkRemovedEnterprisePolicies`); enterprise-only, so a 404 on OSS Kuma is "not served", not a coverage gap |
| **MeshOPA** | top-level `targetRef` kinds other than Mesh/Dataplane, `targetRef.name`/`namespace`/`mesh`, `proxyTypes`; flat `DataSource` (`secret`/`inline`/`inlineString`) in `default.agentConfig` and `default.appendPolicies[].rego` | `kind: Dataplane` + `labels`; typed `SecureDataSource` (`type: Secret` + `secretRef`, `type: InsecureInline` + `insecureInline.value`) | Preflight scans MeshOPA with the generic targetRef-policy checks (`enterprisePolicyPaths`, listed only if served). There is no converter for the data source: 2.14 reads only the flat shape and 3.0 only the typed one, so a 3.0 global syncing to 2.14 zones breaks MeshOPA with either shape. The rewrite has to happen before the global upgrade, on a 2.14 patch that accepts both shapes, not "as part of the upgrade" (blocker) |
| **AccessRole / AccessAudit** (Kong Mesh RBAC) | AccessRole `when[].targetRef.kind` other than Mesh/Dataplane, `when[].from`, `when[].to.targetRef.kind` subset/MeshGateway, `when[].to.targetRef` Mesh*Service/MeshHTTPRoute without `name`, `when[].sources`/`destinations`/`selectors`; `rules[].types` naming a removed kind; `/config` access via `GENERATE_DATAPLANE_TOKEN` | `targetRef` Mesh/Dataplane, `to` Mesh/Mesh*Service/MeshHTTPRoute with `name`; drop removed types; add `VIEW_CONTROL_PLANE_METADATA` | 3.0 rejects all of these on write, so re-applying the role fails (blockers). The removed-kind set is built from the removed-resource catalogs (`removedKindNames`). `targetRef.tags`/`mesh` are reserved in 3.0 but only ever appeared with kinds already flagged (or were never matched on), so they are not reported separately. A qualifier `targetRef.name` becomes a `kuma.io/display-name` label match, which can only shrink the grant, and the 2.14 qualifier has no `labels` to rewrite it with before upgrading, so it is info. `/access-roles` and `/accessaudits` are global; a 404 (OSS) is not a gap, a 403 is |
| **Policy roles** | producer/consumer policy roles | — | role concept dropped |
| **Shadow policies** | — | kept **internal-only** | can't drop (too much e2e coverage); remove only public docs |
| **Policy direction** | `from[]` arrays | `to[]` / `rules[]` | `from` deprecated across many policies (see below), removal targeted for **3.0** |
| **mTLS config** | `Mesh.spec.mtls` backends | `MeshIdentity` + `MeshTrust` | MeshIdentity provisions identity/certs (Bundled / SPIRE / Extension), auto-generates MeshTrust CA bundles. Requires `meshServices.mode: Exclusive` |
| **Zone proxies** | separate `ZoneIngress` + `ZoneEgress` resources | unified **Zone Proxy** (Listener types embedded in Dataplane) | `ZoneIngress`/`ZoneEgress` listener types in `dataplane.proto`. Functions only in Exclusive mode; egress needs WorkloadIdentity. Cross-zone `MeshService` traffic to a zone is down until a **MeshZoneAddress** advertises that zone's address; 2.14 already ships the resource, so create it before upgrading. Preflight requires one per zone that terminates cross-zone traffic |
| **MeshTrafficPermission matching** | `from[].targetRef` (MeshService/MeshSubset) | `rules[]` with `matches[].spiffeID` (Exact/Prefix) + SNI match | Requires MeshIdentity. `from` deprecated, removed in 3.0 |
| **Gateways (ALL types)** | `MeshGateway`, `MeshGatewayInstance`, `MeshGatewayRoute`, builtin gateway, Gateway API / GAMMA support | Kong / third-party gateway as a plain Dataplane with its listen ports excluded from inbound redirection | 3.0 drops Kuma's gateway business entirely, including the 2.x delegated gateway concept — not just builtin. See Gateway section below |
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
| `kdsEventBasedWatchdog.flushInterval` | `..._KDS_EVENT_BASED_WATCHDOG_FLUSH_INTERVAL` | `5s` | moved to `multizone.{global,zone}.kds.eventBasedWatchdog.flushInterval` (`KUMA_MULTIZONE_{GLOBAL,ZONE}_KDS_EVENT_BASED_WATCHDOG_FLUSH_INTERVAL`) — 3.0-only key, so a custom interval cannot be moved before the upgrade; keep the 2.x value (unsetting resets the timing to the default) and set the 3.0 key in the 3.0 configuration |
| `kdsEventBasedWatchdog.fullResyncInterval` | `..._KDS_EVENT_BASED_WATCHDOG_FULL_RESYNC_INTERVAL` | `1m0s` | moved to `multizone.{global,zone}.kds.eventBasedWatchdog.fullResyncInterval` (`KUMA_MULTIZONE_{GLOBAL,ZONE}_KDS_EVENT_BASED_WATCHDOG_FULL_RESYNC_INTERVAL`) — same 3.0-only limitation as `flushInterval` |
| `ingressTagFilters` | `..._INGRESS_TAG_FILTERS` | `[]` | tuning knob — trims ZoneIngress tag size (not a boolean default flip) |

Outside `experimental:`, `defaults.restrictOutbound` (`KUMA_DEFAULTS_RESTRICT_OUTBOUND`) follows the same shape: `false` on 2.14, `true` in 3.0. Preflight tells the three states apart, because since kumahq/kuma#18862 `GET /config` serves the field as `null` when unset (a CP predating the backport — every 2.14 patch up to and including 2.14.5 — omits it, which reads the same). **Unset** gets an info note that the default flips, and its proxies stay blockers. An explicit **`false`** is honored by 3.0, so it gets an info note to carry the setting into the 3.0 configuration, and its proxies drop to info. Once a control plane sets it to `true` the note goes away and the upgrade changes nothing for outbound: a proxy with no `reachableBackends` drops to info (reaching nothing is correct for a workload that calls nothing in the mesh; for any other, setting the field is recommended for security and performance), and so does a mesh with no MeshPassthrough, worded in the present tense. See Outbound denied by default above.

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
  - backend `builtin` → `provider.type: Bundled`, `provided` → `Bundled` with `bundled.ca`, `vault`/`acmpca`/`certmanager` → `Extension` with the same `extension.name` (Kong Mesh)
- `Mesh.spec.routing.localityAwareLoadBalancing` → **MeshLoadBalancingStrategy** (see core table)
- Passthrough setting (`Mesh.spec.networking.outbound` passthrough) → **MeshPassthrough**
- `Mesh.spec.routing.zoneEgress` boolean (`mesh.proto:289`) → dropped
- `Mesh.spec.routing.defaultForbidMeshExternalServiceAccess` (`mesh.proto:293`) → dropped
- Mesh membership / `Mesh.spec.constraints.dataplaneProxy` (`mesh.proto:62-92`) → dropped
- `Mesh.spec.skipCreatingInitialPolicies` (`mesh.proto:8`) → dropped (kumahq/kuma#18661): 3.0 creates no default policies for new Meshes at all, ignores the field, and the first write to the Mesh drops it. Drop it from Mesh manifests before upgrading; rolling back to 2.14 after that recreates the mesh's default policies (`mesh-timeout-all-*`, `mesh-timeout-to-all-*`, `mesh-circuit-breaker-all-*`, `mesh-retry-all-*`), including for a mesh whose list deliberately suppressed them

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
- **`proxyTypes` in targetRef** (`api/common/v1alpha1/targetref.go:101`) → dropped (Gateway/Sidecar proxy-type filtering). The stored field is pruned, so a policy scoped with it widens to every proxy: the 2.x default `mesh-gateways-timeout-all-<mesh>` (`proxyTypes: [Gateway]`, `streamIdleTimeout: 5s`) then fails every sidecar HTTP response slower than 5s with 504 (kumahq/kuma#18857). Delete it rather than dropping the field. Defaults are generated once per Mesh (Kubernetes marks it `k8s.kuma.io/mesh-defaults-generated`), so a deleted default stays deleted unless the Mesh is recreated; if it is (e.g. GitOps replace), add `MeshTimeout` to its `skipCreatingInitialPolicies`
- **`name` / `namespace` / `mesh` in targetRef and route backendRef** → dropped, selection is by `labels` only (kumahq/kuma#17761, #17756, #17740). A stored name-only ref loses the name: top-level `kind: Dataplane` widens to every Dataplane in the mesh, a `to[]` targetRef or backendRef resolves to nothing. Map `name` → `kuma.io/display-name`, `namespace` → `k8s.kuma.io/namespace`
- **Unknown reserved labels rejected on write** (kumahq/kuma#18759): any `kuma.io/` or `k8s.kuma.io/` label outside `pkg/core/resources/labels/registry.go` fails create/update from users (API and webhook), e.g. `kuma.io/service`, `kuma.io/protocol`, `kuma.io/instance`, `k8s.kuma.io/service-port`. Stored resources keep working, re-applies fail. 2.14-stamped `kuma.io/proxy-type`/`kuma.io/proxy-ready` are dropped by the 3.0 CP itself
- **Selectors on removed labels** (kumahq/kuma#18392, #17864, #18662): Dataplanes no longer carry `kuma.io/service`, `kuma.io/proxy-type`, `kuma.io/gateway` or other reserved labels outside the registry, so a targetRef/backendRef `labels`, MeshService `dataplaneLabels`, MeshMultiZoneService `selector.meshService.matchLabels` or MeshLoadBalancingStrategy `affinityTags` key on one never matches
- **Producer policies** (kumahq/kuma#18848): a policy stays producer (applied mesh-wide, synced across zones) only when every `to[]` item is a MeshService/MeshHTTPRoute selected by exactly `kuma.io/display-name`, `k8s.kuma.io/namespace` (own namespace) and `kuma.io/zone` (own zone); otherwise it silently becomes a namespace-scoped consumer, and mixing both is rejected
- **MeshExternalService requires a MeshIdentity**: a client proxy without a workload identity gets no MeshExternalService cluster and fails with 503 `cluster_not_found`
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
- **MeshHTTPRoute**: a request matching no rule of an applicable route now returns `404` instead of falling through to the destination. A route written only to anchor a MeshTimeout/MeshRetry/MeshAccessLog silently changes traffic; preflight reports routes with no catch-all rule as a **blocker** — add a catch-all rule if the fall-through is intended

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
| `networking.outbound[].backendRef.name` | 2.x resolves the name in the proxy's own zone; 3.0 turns it into a `kuma.io/display-name` label and binds the oldest match in any zone (`pkg/xds/context/backendref_normalization.go`) | `backendRef.labels` including `kuma.io/zone` |
| `networking.transparentProxying.directAccessServices` | only `*` is honored; named services silently ignored (`direct_access_proxy_generator.go`) | `*`, or drop direct access |
| `networking.transparentProxying.reachableServices` | removed | `reachableBackends` (see core table) |

## Outbound denied by default

Two 2.x defaults flip together in 3.0 (kumahq/kuma#18798) so a workload that configures nothing can neither receive traffic (already true — `MeshTLS` defaults to `Strict`) nor send it. One switch governs both: `defaults.restrictOutbound` (`KUMA_DEFAULTS_RESTRICT_OUTBOUND`), which 2.14 backports defaulted to `false` (kumahq/kuma#18851, renamed from `allowAllOutbound` with inverted meaning by kumahq/kuma#18861 — it ships in the first patch after 2.14.5) and 3.0 defaults to `true`. Setting it to `true` on 2.14 enforces the 3.0 behavior on the current control plane, which is the migration path: surface and fix the breakage before the upgrade rather than during it. Unlike every other item here these are **absence**-triggered — the resource that breaks carries no configuration at all — so preflight reports each as one summary blocker ("N of M"), and flags the switch itself under Experimental config below.

| Default | 2.x behavior | 3.0 behavior | What to do before upgrading |
|---|---|---|---|
| `networking.transparentProxying.reachableBackends` unset | every destination in the mesh (`destination_index.go`) | no outbounds at all; a Dataplane with no `transparentProxying` section is treated the same way for transparent-proxy proxies (kumahq/kuma#18800). Preflight reads transparent proxying from kuma-dp's reported metadata, then the spec's redirect ports, and counts a Kubernetes sidecar with neither (every injected sidecar runs one) | list, by `labels` (3.0 drops `name`/`namespace` refs), the MeshServices each workload actually calls — `kuma.io/reachable-backends` Pod annotation on Kubernetes, `networking.transparentProxying.reachableBackends.refs` on Universal. An outbound with a `backendRef` short-circuits resolution and is unaffected, as is an explicitly empty `refs` list (the shape zone proxies already ship) |
| no **MeshPassthrough** matches a proxy | passthrough cluster still created, so the effective default is `passthroughMode: All` (`transparent_proxy_generator.go` adds it, the plugin removes it) | the no-policy case behaves like `None` and external egress is dropped (kumahq/kuma#18801) | add a MeshPassthrough selecting every proxy that needs external egress — a policy that exists but selects no proxy leaves the same gap. A mesh that already sets `networking.outbound.passthrough: false` has nothing to lose. Preflight reads each policy's selection from the control plane (`/meshes/{mesh}/meshpassthroughs/{name}/_resources/dataplanes`) and flags every transparent proxy none selects |

## Gateway — Kuma exits the gateway business

3.0 has no gateway concept, builtin or delegated: a Kong / third-party gateway is a plain Dataplane whose listen ports are excluded from inbound redirection (`traffic.kuma.io/exclude-inbound-ports` Pod annotation on Kubernetes, plus the `kuma.io/ignore: "true"` annotation on its fronting Service; `kuma-dp --exclude-inbound-ports` on Universal), see the `dataplane.proto` comment on the reserved `gateway = 3`. Dropped:

- **MeshGateway**, **MeshGatewayInstance**, **MeshGatewayRoute**
- Builtin gateway type
- Gateway API + GAMMA built-in support
- `proxyTypes` in policy targetRef (see targetRef section)
- `networking.gateway` section in Dataplane and the `kuma.io/gateway` marking (see below)

## Observability

- Old observability config → only **KRI-based** config (ties to unified naming)
- Metrics via Dataplane annotations → **MeshMetric**
- `install observability` command/feature → dropped; dashboards shipped inside the release `tar.gz`
- ConfigMap reconcilers → dropped
- Virtual probes cleanup (app-probe-proxy path; cf. Dataplane `spec.probes`)

## Infrastructure / deployment

- **Global CP on Kubernetes** → dropped as supported deployment mode. The fix is `environment: universal` (a Postgres-backed global), `mode` stays `global`. Moving is not rename-free: a Kubernetes global stamps `k8s.kuma.io/namespace` on global-origin resources, which feeds the KDS name hash and the KRI, so their names change in every zone
- **Upgrade order** → the global is upgraded first, and a 3.0 global sends 2.x zones an empty list for every removed resource type (the zones delete their copies) and syncs Mesh and policies with removed fields dropped. Every resource, Mesh and policy-field blocker is therefore a deadline for the global upgrade. Manual check
- **Delta xDS** → the only option (SOTW path removed, not just defaulted on). `experimental.deltaXds` reaches pods only through the Kubernetes injector; Universal kuma-dp and zone proxies started outside it need `KUMA_DATAPLANE_RUNTIME_ENVOY_XDS_TRANSPORT_PROTOCOL_VARIANT=DELTA_GRPC`. Preflight flags each proxy that does not advertise `feature-delta-grpc`
- **`KUMA_DATAPLANE_RUNTIME_REUSE_PORT_ENABLED=false` / `STRICT_INBOUND_PORTS_ENABLED=false`** → 3.0 always sets both, and Envoy rejects `enable_reuse_port` changes on live listeners. Preflight flags proxies missing `feature-reuse-port` or `feature-strict-inbound-ports`
- **`KUMA_DATAPLANE_RUNTIME_OTEL_PIPE_ENABLED=false`** → 3.0 always exports OpenTelemetry through kuma-dp. Preflight flags proxies missing `feature-otel-via-kuma-dp`
- **Legacy transparent proxy annotations with CNI** → the 3.0 CNI plugin reads only `traffic.kuma.io/transparent-proxy-config`, which the 2.x injector writes only with `transparentProxy.configMap.enabled` (`app/cni/pkg/cni/main_linux.go`). Preflight flags a CNI control plane without the ConfigMap and each Kubernetes sidecar missing `feature-transparent-proxy-in-dataplane-metadata`
- **CoreDNS + Envoy DNS filter** → dropped (DNS handling reworked)
- **eBPF** transparent proxy → dropped
- **Legacy inspect and overview endpoints** → removed (`dataplanes/{name}/rules`, `{policy}/{name}/dataplanes`, `meshservices/{name}/_resources/dataplanes`, `dataplanes+insights`, `zones+insights`, zone proxy overviews and Envoy admin, `service-insights`); `_rules` stays without `toRules`/`fromRules`, `dataplanes/{name}/policies` is deprecated but still served. Manual check with the replacement mapping
- **Pod resources** instead of container resources
- **`KUMA_RUNTIME_KUBERNETES_INJECTOR_BUILTIN_DNS_LOGGING`** (embedded DNS logging) → dropped
- Routing MeshExternalService through a specific zone → dropped. Preflight flags zone-origin MeshExternalServices: every zone's egress must reach the endpoint
- **MeshHTTPRoute `backendRefs: []`** → 2.x routes the rule to the destination, 3.0 answers `500` (explicit empty list = all backends unresolved). Preflight blocker
- **Tag-bound dataplane tokens** (`kumactl generate dataplane-token --tag`) → 3.0 checks the tags against Dataplane labels instead of inbound tags, and `kuma.io/service` is not an allowed label, so the proxy is rejected on reconnect. Manual check
- **Universal Helm loopback admin** → the chart sets `KUMA_API_SERVER_AUTHN_LOCALHOST_IS_ADMIN=false` in 3.0 (2.x left the built-in default `true`). `kubectl exec`/`port-forward` + kumactl without a token stops working, and the bootstrap admin token can only be read over loopback *before* the upgrade. Not observable from the API — manual check
- **`apiServer.authn.type: adminClientCerts`** (`KUMA_API_SERVER_AUTHN_TYPE`) → removed (kumahq/kuma#17906). 3.0 registers only the `tokens` authn plugin, so the CP exits at startup with `there is not implementation of authn named adminClientCerts` (master `pkg/core/bootstrap/bootstrap.go:386`). Switch to `tokens` and issue admin user tokens before upgrading. Checked on every CP, a global included. Preflight blocker
- **`apiServer.auth.clientCertsDir`** (`KUMA_API_SERVER_AUTH_CLIENT_CERTS_DIR`) → removed with it (kumahq/kuma#17906). The 3.0 CP loads its config non-strictly, so the value is silently ignored and client certificates trusted only through that directory stop authenticating to the HTTPS API server. Move the client CA to `apiServer.https.tlsCaFile` and unset the directory. Preflight blocker
- **`bootstrapServer.params.readinessPort: 0`** (`KUMA_BOOTSTRAP_SERVER_PARAMS_READINESS_PORT`) → 2.14 accepts `[0, 65535]`, 3.0 validates `(0, 65535]` (master `pkg/config/xds/bootstrap/config.go:85`, called from `pkg/config/app/kuma-cp/config.go:338` for zone CPs), so the CP fails to start. Set it back to the default `9902` or another free port. Preflight blocker (zone CPs only, a global does not validate it)
- **`experimental.exposeZoneProxyMetrics`** (`KUMA_EXPERIMENTAL_EXPOSE_ZONE_PROXY_METRICS`, 2.14 only, kumahq/kuma#17905) → dropped. 3.0 has no unauthenticated `/stats/prometheus` route on the zone proxy admin listener and ignores the flag, so Prometheus scraping of zone proxies breaks. After moving to mesh-scoped zone proxy Dataplanes, scrape them with MeshMetric and remove the flag. Preflight blocker
- **MADS on Kubernetes** (`monitoringAssignmentServer.enabled`, default `true`) → 3.0 does not start MADS on a Kubernetes CP regardless of the flag (kumahq/kuma#17868, master `pkg/mads/server/server.go:120`), so Prometheus `kuma_sd` discovery against a k8s CP stops working. Universal (including universal-on-Kubernetes) keeps it. Preflight flags a k8s zone CP with MADS on as a blocker: move Prometheus to Kubernetes service discovery with MeshMetric, then set `monitoringAssignmentServer.enabled: false` (Helm `controlPlane.madsServer.enabled: false`) to validate on 2.14. The CP cannot tell whether anything scrapes MADS, so a CP that leaves the default on is flagged too
- **`kmesh.multizone` KDS auth settings** (`KMESH_MULTIZONE_GLOBAL_KDS_AUTH_TYPE`, `KMESH_MULTIZONE_GLOBAL_KDS_AUTH_CP_TOKEN_ENABLE_ISSUER`, `KMESH_MULTIZONE_GLOBAL_KDS_AUTH_CP_TOKEN_VALIDATOR_USE_SECRETS`, `KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_INLINE`, `KMESH_MULTIZONE_ZONE_KDS_AUTH_CP_TOKEN_PATH`) → renamed to the Kuma paths (`KUMA_MULTIZONE_GLOBAL_KDS_AUTH_TYPE` with `zoneToken` in place of `cpToken`, `KUMA_MULTIZONE_GLOBAL_KDS_AUTH_ZONE_TOKEN_*`, `KUMA_MULTIZONE_ZONE_KDS_AUTH_TOKEN_INLINE`/`_TOKEN_PATH`) on 2.14.6 (Kong/kong-mesh#10960) and removed in 3.0: the 3.0 CP exits at startup when a `KMESH_MULTIZONE_*` variable is set, and silently ignores the `kmesh.multizone` config keys, so a global left on the old names serves KDS without authentication (`multizone.global.kds.auth.type` defaults to `none`) and a zone without the new inline/path token is rejected by the global. 2.14.6 mirrors the effective values into both the `multizone.*` and `kmesh.multizone.*` paths of `/config`, so the control plane's startup-log deprecation lines (`kmesh.multizone... is deprecated, use ... instead`) are the only signal naming the settings that still use the old names. Preflight flags every non-default `kmesh.multizone` KDS auth value as a blocker and points at the new names; leftover old variables abort the 3.0 startup even when the new ones are set too

## Naming / identity / misc

- **Legacy `kuma.io/service` tag routing** → MeshService resources + explicit BackendRef (`LegacyOutbound` in `pkg/core/xds/types/outbound.go`)
- **`ServiceTag` MeshService identities** → 3.0 accepts only `SpiffeID` (CRD enum), so a 3.0 Kubernetes zone refuses a MeshService synced from a 2.14 zone that still lists one: a create is skipped, an identity update fails that zone's MeshService sync. 2.14 zone CPs write the entry from the `kuma.io/service` tag, or from the `kuma.io/workload` label with inbound tags disabled, and until kumahq/kuma#18920 even without Mesh `mtls`. Preflight flags a hand-written MeshService that declares one; a generated MeshService is rewritten by its zone CP, so a stale entry is covered by the version-currency blocker once a 2.14 patch carries kumahq/kuma#18920
- **Non-RFC-1035 resource names** deprecated for Mesh, Zone, MeshService, MeshExternalService, MeshMultiZoneService (`deprecated.go` per resource). For **Zone** it is stricter than a deprecation: a 3.0 zone CP refuses to start on a non-label name (`pkg/config/multizone/multicluster.go`) and the global rejects it on connect (`pkg/core/resources/apis/system/zone_validator.go`), while the Helm chart still accepts dots — so `eu.west` passes `helm upgrade` and then crash-loops. Preflight reads `/zones` on a global, falling back to `multizone.zone.name` in `/config` on a directly audited zone CP
- **MeshMultiZoneService**: names > 63 chars deprecated
- **`kuma.io/mesh` annotation** on Pods, Namespaces, Services and Gateway API HTTPRoutes → use label (3.0 reads only the label)
- **MeshGatewayInstance**: `kuma.io/service` tag → auto-generated `serviceName`
- **Dataplane `spec.probes`** and virtual probes → removed (kumahq/kuma#17901). On Universal drop the field; on Kubernetes `spec.probes` marks a pod with virtual probes enabled; when Application Probe Proxy is off for it (`kuma.io/application-probe-proxy-port: "0"`) its rewritten kubelet probes fail on 3.0 until re-injected, so move it to Application Probe Proxy first. The Dataplane alone cannot tell the two apart, so every such pod is flagged
- **`kuma.io/protocol` inbound tag** no longer sets the protocol (kumahq/kuma#17861): a Universal inbound without `networking.inbound[].protocol` is served as plain TCP and loses its L7 filters. Inbound `protocol: kafka` is rejected (kumahq/kuma#17831)
- **Unix-socket readiness** removed (kumahq/kuma#18637): a kuma-dp older than 2.14 advertising `feature-readiness-unix-socket` never reports ready against a 3.0 CP
- **`kuma.io/gateway` removed** (kumahq/kuma#18662): the Pod annotation, the Dataplane label and `networking.gateway` are all gone. A marked gateway becomes an ordinary workload whose inbound traffic is redirected through Envoy, so MeshTrafficPermission rejects clients outside the mesh. A leftover `kuma.io/gateway` Dataplane label is stripped when the control plane writes the Dataplane, kuma-dp registration included (`removedLabels` in `pkg/core/resources/labels/compute.go`), but a user write through the REST API, `kumactl apply` or the k8s webhook rejects it as an unknown reserved label (`validateSyntax` in `pkg/core/resources/labels/validate.go`), so a `targetRef` or MeshLoadBalancingStrategy affinity key selecting on it stops matching. Replace the marking with `traffic.kuma.io/exclude-inbound-ports` listing every listen port (k8s; plus `kuma.io/ignore: "true"` on the fronting Service) or `kuma-dp --exclude-inbound-ports` (Universal). The MeshMetric `gateway` proxy role and the `?gateway=` overview filter go with it. Preflight flags k8s Dataplanes with `networking.gateway` and Universal Dataplanes with `networking.gateway` or the label
- **`k8s.kuma.io/service-account`** is control-plane-owned in 3.0: the admission webhook rejects a user-applied resource carrying it (unless the caller is the CP or in `runtime.kubernetes.allowedUsers`) and xDS auth refuses a proxy whose label does not match its Pod's ServiceAccount. Preflight flags it on Universal Dataplanes (where it has no source at all); the GitOps-on-Kubernetes case is a manual check, since a CP-created Dataplane legitimately carries it
- **`kuma.io/tags` Pod annotation** → no reader in 3.0 (`pkg/plugins/runtime/k8s/metadata/annotations.go`); it is ignored rather than warned about. Manual check
- **Legacy HMAC256 signing keys** (pre-1.4.x) → asymmetric RSA/ECDSA (`pkg/core/tokens/signing_key_accessor.go`)

