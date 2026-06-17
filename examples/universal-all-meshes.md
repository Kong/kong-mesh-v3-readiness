# Kuma 3.0 Upgrade Pre-flight Report

- Control plane: Kuma 2.14.0-preview.vce3b1275a
- Meshes scanned: 1badname, clean, default, legacy
- Findings: 24 blockers, 36 warnings, 0 info

❌ Blockers found. Resolve them before upgrading to 3.0.

## Blockers — must resolve before upgrading

### Mesh object settings

- **Inline logging on Mesh** — 1 found. Replace `mesh.logging` with the MeshAccessLog policy.
  - e.g. legacy (logging)
- **Inline mTLS on Mesh** — 1 found. Migrate `mesh.mtls` to MeshIdentity + MeshTrust.
  - e.g. legacy (mtls)
- **Inline metrics on Mesh** — 1 found. Replace `mesh.metrics` with the MeshMetric policy.
  - e.g. legacy (metrics)
- **Inline tracing on Mesh** — 1 found. Replace `mesh.tracing` with the MeshTrace policy.
  - e.g. legacy (tracing)
- **Mesh membership constraints** — 1 found. `mesh.constraints` (membership) is removed.
  - e.g. legacy (constraints)
- **Passthrough on Mesh** — 1 found. `mesh.networking.outbound.passthrough` is removed; use MeshPassthrough.
  - e.g. legacy (networking.outbound.passthrough)
- **defaultForbidMeshExternalServiceAccess on Mesh** — 1 found. `mesh.routing.defaultForbidMeshExternalServiceAccess` is removed.
  - e.g. legacy (routing.defaultForbidMeshExternalServiceAccess)
- **localityAwareLoadBalancing on Mesh** — 1 found. Replace with MeshLoadBalancingStrategy.
  - e.g. legacy (routing.localityAwareLoadBalancing)
- **routing.zoneEgress on Mesh** — 1 found. `mesh.routing.zoneEgress` is removed.
  - e.g. legacy (routing.zoneEgress)
### Policy `from` field

- **MeshTimeout uses `from`** — 8 found. Rewrite `from` as `rules` (with spiffeID where applicable).
  - e.g. 1badname/mesh-gateways-timeout-all-1badname, 1badname/mesh-timeout-all-1badname, clean/mesh-gateways-timeout-all-clean, clean/mesh-timeout-all-clean, default/mesh-gateways-timeout-all-default, default/mesh-timeout-all-default, legacy/mesh-gateways-timeout-all-legacy, legacy/mesh-timeout-all-legacy
- **MeshTrafficPermission uses `from`** — 1 found. Rewrite `from` as `rules` (with spiffeID where applicable).
  - e.g. legacy/mtp-from
### Removed resources

- **ExternalService (removed in 3.0)** — 1 found. Replace with MeshExternalService.
  - e.g. default/es-legacy
- **ProxyTemplate (removed in 3.0)** — 1 found. Replace with MeshProxyPatch.
  - e.g. default/pt-legacy
- **TrafficPermission (removed in 3.0)** — 1 found. Replace with MeshTrafficPermission (rules + spiffeID).
  - e.g. default/tp-legacy
- **TrafficRoute (removed in 3.0)** — 1 found. Replace with MeshHTTPRoute / MeshTCPRoute.
  - e.g. default/tr-legacy
### Top-level targetRef kind

- **MeshHTTPRoute top-level targetRef.kind=MeshService** — 1 found. Top-level targetRef must be Mesh or Dataplane; use labels.
  - e.g. legacy/mhr-badtargetref
### reachableServices

- **Dataplane uses reachableServices** — 1 found. Replace `reachableServices` with `reachableBackends` (MeshService-based).
  - e.g. default/dp-uni

## Warnings — should resolve

### Dataplane probes

- **Dataplane has a probes section** — 1 found. Dataplane `spec.probes` is removed for Universal in 3.0 (app-probe-proxy supersedes it).
  - e.g. default/dp-uni
### MeshService mode

- **meshServices.mode is not Exclusive** — 3 found. Move to `meshServices.mode: Exclusive` before upgrading (current: Disabled).
  - e.g. 1badname, default, legacy
### Non-RFC-1035 names

- **Mesh name is not a valid RFC-1035 DNS label** — 1 found. Rename to a lowercase RFC-1035 DNS label (≤63 chars, starting with a letter); non-conforming names are deprecated in 3.0.
  - e.g. 1badname
### OpenTelemetry endpoint

- **MeshAccessLog uses OpenTelemetry `endpoint`** — 1 found. The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).
  - e.g. default/mal-otel
- **MeshMetric uses OpenTelemetry `endpoint`** — 1 found. The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).
  - e.g. default/mm-otel
- **MeshTrace uses OpenTelemetry `endpoint`** — 1 found. The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).
  - e.g. default/mt-otel
### Relocated policy fields

- **MeshHealthCheck uses healthyPanicThreshold** — 1 found. `healthyPanicThreshold` moves to MeshCircuitBreaker in 3.0.
  - e.g. default/mhc-panic
- **MeshLoadBalancingStrategy nests hashPolicies under loadBalancer** — 1 found. Move `loadBalancer.{ringHash,maglev}.hashPolicies` up to `to[].default.hashPolicies`.
  - e.g. default/mlbs-srcip
- **MeshLoadBalancingStrategy uses SourceIP hash policy** — 1 found. The `SourceIP` hash policy type is deprecated; use `Connection`.
  - e.g. default/mlbs-srcip
### `to` targetRef kind

- **MeshAccessLog to[].targetRef.kind=Mesh** — 1 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. default/mal-otel
- **MeshCircuitBreaker to[].targetRef.kind=Mesh** — 4 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. 1badname/mesh-circuit-breaker-all-1badname, clean/mesh-circuit-breaker-all-clean, default/mesh-circuit-breaker-all-default, legacy/mesh-circuit-breaker-all-legacy
- **MeshRetry to[].targetRef.kind=Mesh** — 4 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. 1badname/mesh-retry-all-1badname, clean/mesh-retry-all-clean, default/mesh-retry-all-default, legacy/mesh-retry-all-legacy
- **MeshTimeout to[].targetRef.kind=Mesh** — 8 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. 1badname/mesh-gateways-timeout-all-1badname, 1badname/mesh-timeout-all-1badname, clean/mesh-gateways-timeout-all-clean, clean/mesh-timeout-all-clean, default/mesh-gateways-timeout-all-default, default/mesh-timeout-all-default, legacy/mesh-gateways-timeout-all-legacy, legacy/mesh-timeout-all-legacy
### targetRef proxyTypes

- **MeshTimeout uses targetRef.proxyTypes** — 8 found. `proxyTypes` is removed (gateway support dropped).
  - e.g. 1badname/mesh-gateways-timeout-all-1badname, 1badname/mesh-timeout-all-1badname, clean/mesh-gateways-timeout-all-clean, clean/mesh-timeout-all-clean, default/mesh-gateways-timeout-all-default, default/mesh-timeout-all-default, legacy/mesh-gateways-timeout-all-legacy, legacy/mesh-timeout-all-legacy

## Manual checks (not detectable via the CP API)

- [ ] Unified resource naming enabled (`dataPlane.features.unifiedResourceNaming: true`)
- [ ] Inbound tags disabled (`KUMA_EXPERIMENTAL_INBOUND_TAGS_DISABLED=true`)
- [ ] Experimental flags moved to defaults: deltaXds (becomes the only option), kdsEventBasedWatchdog, sidecarContainers
- [ ] autoReachableServices removed entirely — stop relying on it
- [ ] Global control plane on Kubernetes is dropped as a deployment mode
- [ ] Gateway API / GAMMA usage migrated off built-in support
- [ ] Observability: KRI-based config only; `install observability` command removed; metrics-via-Dataplane-annotations removed
- [ ] DNS: CoreDNS + Envoy DNS filter removed; eBPF transparent proxy removed
- [ ] Old inspect APIs removed (switch to the new inspect API)
- [ ] Pod resources instead of container resources
- [ ] Adopt the Workload resource for proxy grouping (metrics/traces dimension) instead of kuma.io/service tags
- [ ] Rotate legacy HMAC256 signing keys (pre-1.4.x) to asymmetric RSA/ECDSA
- [ ] Replace the `kuma.io/mesh` annotation with the `kuma.io/mesh` label
- [ ] Routing MeshExternalService through a specific zone is removed

_Source of truth: `docs/deprecated-features.md`._
