# Kuma 3.0 Upgrade Pre-flight Report

- Control plane: Kuma 0.0.0-preview.vabc376b0a
- Meshes scanned: 1badname, clean, default, legacy
- Findings: 30 blockers, 35 warnings, 0 info
- Includes 18 CP-managed (policy-role: system) resource(s) — update these before upgrading


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
  - e.g. 1badname/mesh-gateways-timeout-all-1badname.kuma-system (system — CP-managed, update before 3.0), 1badname/mesh-timeout-all-1badname.kuma-system (system — CP-managed, update before 3.0), clean/mesh-gateways-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), clean/mesh-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), default/mesh-gateways-timeout-all-default.kuma-system (system — CP-managed, update before 3.0), default/mesh-timeout-all-default.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-gateways-timeout-all-legacy.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-timeout-all-legacy.kuma-system (system — CP-managed, update before 3.0)
- **MeshTrafficPermission uses `from`** — 2 found. Rewrite `from` as `rules` (with spiffeID where applicable).
  - e.g. default/mtp-user-from.k3pf-test, legacy/mtp-from-legacy.kuma-system (system — CP-managed, update before 3.0)
### Removed resources

- **CircuitBreaker (removed in 3.0)** — 1 found. Replace with MeshCircuitBreaker.
  - e.g. default/cb-legacy
- **ExternalService (removed in 3.0)** — 1 found. Replace with MeshExternalService.
  - e.g. default/es-legacy
- **HealthCheck (removed in 3.0)** — 1 found. Replace with MeshHealthCheck.
  - e.g. default/hc-legacy
- **ProxyTemplate (removed in 3.0)** — 1 found. Replace with MeshProxyPatch.
  - e.g. default/pt-legacy
- **Timeout (removed in 3.0)** — 1 found. Replace with MeshTimeout.
  - e.g. default/to-legacy
- **TrafficLog (removed in 3.0)** — 1 found. Replace with MeshAccessLog.
  - e.g. default/tl-legacy
- **TrafficPermission (removed in 3.0)** — 1 found. Replace with MeshTrafficPermission (rules + spiffeID).
  - e.g. default/tp-legacy
- **TrafficRoute (removed in 3.0)** — 1 found. Replace with MeshHTTPRoute / MeshTCPRoute.
  - e.g. default/tr-legacy
- **VirtualOutbound (removed in 3.0)** — 1 found. Replace with unified naming + MeshService hostnames.
  - e.g. default/vo-legacy
### Top-level targetRef kind

- **MeshHTTPRoute top-level targetRef.kind=MeshService** — 1 found. Top-level targetRef must be Mesh or Dataplane; use labels.
  - e.g. legacy/mhr-badtargetref.kuma-system (system — CP-managed, update before 3.0)
### reachableServices

- **Dataplane uses reachableServices** — 1 found. Replace `reachableServices` with `reachableBackends` (MeshService-based).
  - e.g. default/reachable-app-55446f777c-p5b9f.k3pf-test

## Warnings — should resolve

### MeshService mode

- **meshServices.mode is not Exclusive** — 3 found. Move to `meshServices.mode: Exclusive` before upgrading (current: Disabled).
  - e.g. 1badname, default, legacy
### Non-RFC-1035 names

- **Mesh name is not a valid RFC-1035 DNS label** — 1 found. Rename to a lowercase RFC-1035 DNS label (≤63 chars, starting with a letter); non-conforming names are deprecated in 3.0.
  - e.g. 1badname
### OpenTelemetry endpoint

- **MeshAccessLog uses OpenTelemetry `endpoint`** — 1 found. The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).
  - e.g. default/mal-otel.k3pf-test
- **MeshMetric uses OpenTelemetry `endpoint`** — 1 found. The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).
  - e.g. default/mm-otel.k3pf-test
- **MeshTrace uses OpenTelemetry `endpoint`** — 1 found. The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).
  - e.g. default/mt-otel.k3pf-test
### Relocated policy fields

- **MeshHealthCheck uses healthyPanicThreshold** — 1 found. `healthyPanicThreshold` moves to MeshCircuitBreaker in 3.0.
  - e.g. default/mhc-panic.k3pf-test
- **MeshLoadBalancingStrategy nests hashPolicies under loadBalancer** — 1 found. Move `loadBalancer.{ringHash,maglev}.hashPolicies` up to `to[].default.hashPolicies`.
  - e.g. default/mlbs-srcip.k3pf-test
- **MeshLoadBalancingStrategy uses SourceIP hash policy** — 1 found. The `SourceIP` hash policy type is deprecated; use `Connection`.
  - e.g. default/mlbs-srcip.k3pf-test
### `to` targetRef kind

- **MeshAccessLog to[].targetRef.kind=Mesh** — 1 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. default/mal-otel.k3pf-test
- **MeshCircuitBreaker to[].targetRef.kind=Mesh** — 4 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. 1badname/mesh-circuit-breaker-all-1badname.kuma-system (system — CP-managed, update before 3.0), clean/mesh-circuit-breaker-all-clean.kuma-system (system — CP-managed, update before 3.0), default/mesh-circuit-breaker-all-default.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-circuit-breaker-all-legacy.kuma-system (system — CP-managed, update before 3.0)
- **MeshRetry to[].targetRef.kind=Mesh** — 4 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. 1badname/mesh-retry-all-1badname.kuma-system (system — CP-managed, update before 3.0), clean/mesh-retry-all-clean.kuma-system (system — CP-managed, update before 3.0), default/mesh-retry-all-default.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-retry-all-legacy.kuma-system (system — CP-managed, update before 3.0)
- **MeshTimeout to[].targetRef.kind=Mesh** — 8 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. 1badname/mesh-gateways-timeout-all-1badname.kuma-system (system — CP-managed, update before 3.0), 1badname/mesh-timeout-all-1badname.kuma-system (system — CP-managed, update before 3.0), clean/mesh-gateways-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), clean/mesh-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), default/mesh-gateways-timeout-all-default.kuma-system (system — CP-managed, update before 3.0), default/mesh-timeout-all-default.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-gateways-timeout-all-legacy.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-timeout-all-legacy.kuma-system (system — CP-managed, update before 3.0)
### targetRef proxyTypes

- **MeshTimeout uses targetRef.proxyTypes** — 8 found. `proxyTypes` is removed (gateway support dropped).
  - e.g. 1badname/mesh-gateways-timeout-all-1badname.kuma-system (system — CP-managed, update before 3.0), 1badname/mesh-timeout-all-1badname.kuma-system (system — CP-managed, update before 3.0), clean/mesh-gateways-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), clean/mesh-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), default/mesh-gateways-timeout-all-default.kuma-system (system — CP-managed, update before 3.0), default/mesh-timeout-all-default.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-gateways-timeout-all-legacy.kuma-system (system — CP-managed, update before 3.0), legacy/mesh-timeout-all-legacy.kuma-system (system — CP-managed, update before 3.0)

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
