# legacy-estate — a 2.14 estate built to break on 3.0

Fixtures for exercising a 2.14 → 3.0 migration script. Every resource here is something 3.0 removes, relocates, or renames, laid out over [kuma-counter-demo](https://github.com/kumahq/kuma-counter-demo) running in both Kubernetes zones with a builtin gateway in front.

Topology assumed: **Konnect global CP** (`migration/zone-1.yaml`), two **k8s zone CPs** federated to it.

```
edge-gateway (builtin, both zones)
        |
        v
  demo-app  --(canary v1/v2)-->  demo-app       demo-app --> es-httpbin-legacy
        |
        v
       kv

one mesh: `default`, meshServices.mode Everywhere
ns kuma-demo: sidecar-injection label + the deprecated kuma.io/mesh ANNOTATION
```

`version: v2` runs **only in zone-1**, so every v2 subset selector has to resolve cross-zone. That is what gives `localityAwareLoadBalancing`, the ZoneIngress path and the MeshMultiZoneService something to actually do.

## Global or zone — this is not a style choice

A federated zone CP treats a resource type as **read-only unless its KDS flags carry `ProvidedByZoneFlag`** (`ResourceTypeDescriptor.IsReadOnly`). That single rule decides where every file below has to be applied:

| Type                                                                                                                                       | KDS flags (2.14)                | Where                                           |
|:-------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------|:------------------------------------------------|
| `Mesh`, all 13 legacy selector policies, `ExternalService`, `ProxyTemplate`, `VirtualOutbound`, `MeshGatewayRoute`, `MeshMultiZoneService` | `GlobalToZones`                 | **global only** — the zone webhook rejects them |
| `MeshGateway`                                                                                                                              | `GlobalToZones \| ZoneToGlobal` | either; here **zone** (per-zone gateway)        |
| targetRef policies (`MeshTimeout`, `MeshTrafficPermission`, …), `MeshExternalService`, `MeshTrust`, `MeshPassthrough`                      | `GlobalToZones \| ZoneToGlobal` | either; split deliberately across both          |
| `MeshGatewayInstance`                                                                                                                      | k8s CRD, never synced           | **zone only**                                   |
| `Dataplane`, `ZoneIngress`, `ZoneEgress`                                                                                                   | `ZoneToGlobal`                  | **zone only** (helm / injector creates them)    |

Two zone-webhook rules a migration script must preserve:

- A targetRef policy in the **system namespace** on a zone CP requires `kuma.io/origin: zone`. Without it the webhook returns `403 Applying policies on Zone CP on a system namespace requires 'kuma.io/origin' label to be set to 'zone'`.
- A targetRef policy in an **application namespace** instead gets a computed policy **role** (producer / consumer) — a concept 3.0 drops entirely.

## Files

| File | Applied to | Carries |
|---|---|---|
| `global/00-meshes.yaml` | global | `default` — inline mtls/metrics/tracing/logging/routing/passthrough/constraints, `meshServices.mode: Everywhere` |
| `global/01-removed-policies.yaml` | global | all 13 removed selector policies + `ExternalService` + `MeshGatewayRoute` |
| `global/02-targetref-deprecated.yaml` | global | kinds that survive with a spec that does not: `from[]`, top-level targetRef kinds, `proxyTypes`, OTel `endpoint`, relocated fields, `MeshTrust.spec.origin` |
| `global/03-enterprise.yaml` | global | `MeshGlobalRateLimit` (removed, no replacement) and `MeshOPA` — Kong Mesh only, absent from Kuma's UPGRADE.md |
| `global/04-services-and-names.yaml` | global | `MeshExternalService` (per-zone routing + dotted name), `MeshMultiZoneService` (66-char name), `HostnameGenerator`, `MeshPassthrough` |
| `zone/zone-1/00-counter-demo.yaml` | zone-1 | counter-demo in `kuma-demo`, v1+v2, legacy pod and namespace annotations |
| `zone/zone-2/00-counter-demo.yaml` | zone-2 | same, v1 only |
| `zone/zone-*/01-gateway.yaml` | each zone | `MeshGateway` + `MeshGatewayInstance` + the `MeshHTTPRoute` that serves it; zone-2 also carries the `MeshTrafficPermission` that overrides `mtp-from-service`'s zone-2 deny for its own gateway |
| `zone/zone-1/02-uni-zone-route.yaml` | zone-1 | `/uni` on zone-1's gateway routed cross-zone to `uni-demo-app` in the Universal zone |
| `zone/02-zone-policies.yaml` | both zones | zone-origin targetRef policies + one namespaced producer-role policy |
| `zone/zone-*/zone-*.yaml` | helm | CP flags pinned to the 2.14 customer default, not the 3.0 target. No numeric prefix, so `apply.sh`'s `[0-9]*.yaml` glob skips it |
| `universal-gcp/` | a Universal zone on GCE | Terraform for the whole Universal zone and the checks only it can carry — skip on a k8s-only estate |

## Apply

```bash
kubectl create namespace kong-mesh-system                    # each zone
kubectl -n kong-mesh-system create secret generic cp-token \
  --from-literal=token='<konnect zone token>'                # each zone
helm upgrade --install -n kong-mesh-system kong-mesh kong-mesh/kong-mesh \
  --version 2.14.3 -f zone/values/zone-1-values.yaml         # then zone-2

GLOBAL_CTX=<kumactl cp name> ZONE1_CTX=k3d-zone1 ZONE2_CTX=k3d-zone2 ./apply.sh
```

Order matters in one place only: `00-meshes.yaml` before everything else, because every policy references a mesh.

## What it should produce

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight
bin/kuma3-preflight --address <konnect-cp-api> --token <token> --output report.html
```

Expected blocker categories, and the file each comes from:

| preflight category                                                                          | Source                                                   |
|:--------------------------------------------------------------------------------------------|:---------------------------------------------------------|
| Removed policies · Removed resources                                                        | `global/01`                                              |
| Mesh object settings (7 findings) · MeshService mode                                        | `global/00`                                              |
| Policy `from` field · Top-level targetRef kind · targetRef proxyTypes                       | `global/02`, `zone/02`, `zone/*/01`                      |
| OpenTelemetry endpoint · Relocated policy fields                                            | `global/02`                                              |
| Non-RFC-1035 names                                                                          | `global/04`                                              |
| reachableServices · Dataplane metrics                                                       | `zone/*/00` pod annotations                              |
| Zone proxies                                                                                | `ingress.enabled` / `egress.enabled` in the values files |
| Control plane configuration (6 findings)                                                    | `zone/values/*`                                          |

## What is deliberately not here

- **The whole `to targetRef kind` category.** preflight flags subset/selector and `MeshGateway` kinds in `to[]`, but no 2.14 policy schema accepts any of them there — every policy's `to[]` union is already a subset of what 3.0 keeps, so the CP rejects the fixture at admission. The finding is only reachable on a CP carrying data written by an older version.
- **eBPF transparent proxy.** A blocker, but it needs a CNI and a kernel k3d does not provide; enabling it stops every injected pod. Left commented in the values files with the exact key.
- **Global CP on Kubernetes.** A blocker only when global runs on k8s. Global here is Konnect.
- **Universal-only checks.** Dataplane `probes`, the missing `kuma.io/workload` label and legacy `outbound[]` need a Universal zone federated to the same global. [`universal-gcp/`](universal-gcp) is Terraform that stands one up on GCE — zone CP, ZoneIngress, ZoneEgress and the counter demo on explicit outbounds, including outbounds to the k8s zones' service tags.
