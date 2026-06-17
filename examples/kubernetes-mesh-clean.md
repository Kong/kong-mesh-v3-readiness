# Kuma 3.0 Upgrade Pre-flight Report

- Control plane: Kuma 0.0.0-preview.vabc376b0a
- Meshes scanned: clean
- Findings: 2 blockers, 6 warnings, 0 info
- Includes 4 CP-managed (policy-role: system) resource(s) — update these before upgrading


## Blockers — must resolve before upgrading

### Policy `from` field

- **MeshTimeout uses `from`** — 2 found. Rewrite `from` as `rules` (with spiffeID where applicable).
  - e.g. clean/mesh-gateways-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), clean/mesh-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0)

## Warnings — should resolve

### `to` targetRef kind

- **MeshCircuitBreaker to[].targetRef.kind=Mesh** — 1 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. clean/mesh-circuit-breaker-all-clean.kuma-system (system — CP-managed, update before 3.0)
- **MeshRetry to[].targetRef.kind=Mesh** — 1 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. clean/mesh-retry-all-clean.kuma-system (system — CP-managed, update before 3.0)
- **MeshTimeout to[].targetRef.kind=Mesh** — 2 found. `to` may only target MeshService/MeshExternalService/MeshMultiZoneService.
  - e.g. clean/mesh-gateways-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), clean/mesh-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0)
### targetRef proxyTypes

- **MeshTimeout uses targetRef.proxyTypes** — 2 found. `proxyTypes` is removed (gateway support dropped).
  - e.g. clean/mesh-gateways-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0), clean/mesh-timeout-all-clean.kuma-system (system — CP-managed, update before 3.0)

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
