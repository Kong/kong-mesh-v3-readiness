# `kuma3-preflight` — Real-CP Test Environment Setup

Reproducible runbook to stand up the exact k3d Kuma CP + fixtures used to manually
verify `cmd/kuma3-preflight` against a real control plane (see
`test-results.md` "Real control-plane execution" addendum).

All manifests are embedded inline — no external files needed. Tested 2026-06-16 on the
repo at `v2.14.0` (CP build `0.0.0-preview.v<sha>`, a 2.x CP where legacy resources are
still valid and detectable).

> Why a 2.x CP: the tool audits a **2.x** estate for 3.0 readiness. Legacy resources
> (TrafficPermission, ProxyTemplate, …) and inline Mesh settings only exist on 2.x.

---

## 1. Build the binary

```bash
go build -o /tmp/kuma3-preflight ./cmd/kuma3-preflight
```

## 2. Cluster + CP

```bash
cd <repo-root>

# Fresh k3d cluster (deletes any prior kuma-1 first)
k3d cluster delete kuma-1 2>/dev/null
make k3d/cluster/start CLUSTER=kuma-1

export KUBECONFIG=~/.kube/k3d-kuma-1.yaml

# Build images from current HEAD, load into k3d, helm-install the CP (zone, standalone).
# NO_CNI keeps it light for local dev.
make k3d/cluster/deploy/helm CLUSTER=kuma-1 K3D_HELM_DEPLOY_NO_CNI=true

# Verify CP up
kubectl get pods -n kuma-system
kubectl exec -n kuma-system deploy/kuma-control-plane -- wget -qO- localhost:5681/
```

## 3. Port-forward the REST API

The local binary talks to the CP over `:5681`.

```bash
pkill -f "port-forward.*5681" 2>/dev/null
nohup kubectl port-forward -n kuma-system deploy/kuma-control-plane 5681:5681 \
  >/tmp/pf-kuma1.log 2>&1 &
sleep 3
curl -s http://localhost:5681/        # expect product=Kuma, version=...
```

---

## 4. Fixtures

### 4a. Legacy resources (removed in 3.0) — `default` mesh

Exercises `checkLegacyResources` (presence-counted). Apply:

```bash
kubectl apply -f - <<'EOF'
apiVersion: kuma.io/v1alpha1
kind: TrafficPermission
mesh: default
metadata: {name: tp-legacy, namespace: kuma-system}
spec:
  sources: [{match: {kuma.io/service: "*"}}]
  destinations: [{match: {kuma.io/service: "*"}}]
---
apiVersion: kuma.io/v1alpha1
kind: TrafficRoute
mesh: default
metadata: {name: tr-legacy, namespace: kuma-system}
spec:
  sources: [{match: {kuma.io/service: "*"}}]
  destinations: [{match: {kuma.io/service: "*"}}]
  conf: {destination: {kuma.io/service: "*"}}
---
apiVersion: kuma.io/v1alpha1
kind: TrafficLog
mesh: default
metadata: {name: tl-legacy, namespace: kuma-system}
spec:
  sources: [{match: {kuma.io/service: "*"}}]
  destinations: [{match: {kuma.io/service: "*"}}]
---
apiVersion: kuma.io/v1alpha1
kind: HealthCheck
mesh: default
metadata: {name: hc-legacy, namespace: kuma-system}
spec:
  sources: [{match: {kuma.io/service: "*"}}]
  destinations: [{match: {kuma.io/service: "*"}}]
  conf: {interval: 10s, timeout: 2s, unhealthyThreshold: 3, healthyThreshold: 1}
---
apiVersion: kuma.io/v1alpha1
kind: CircuitBreaker
mesh: default
metadata: {name: cb-legacy, namespace: kuma-system}
spec:
  sources: [{match: {kuma.io/service: "*"}}]
  destinations: [{match: {kuma.io/service: "*"}}]
  conf: {detectors: {totalErrors: {consecutive: 20}}}
---
apiVersion: kuma.io/v1alpha1
kind: Timeout
mesh: default
metadata: {name: to-legacy, namespace: kuma-system}
spec:
  sources: [{match: {kuma.io/service: "*"}}]
  destinations: [{match: {kuma.io/service: "*"}}]
  conf: {connectTimeout: 10s}
---
apiVersion: kuma.io/v1alpha1
kind: ProxyTemplate
mesh: default
metadata: {name: pt-legacy, namespace: kuma-system}
spec:
  selectors: [{match: {kuma.io/service: "*"}}]
  conf: {imports: [default-proxy]}
---
apiVersion: kuma.io/v1alpha1
kind: ExternalService
mesh: default
metadata: {name: es-legacy, namespace: kuma-system}
spec:
  networking: {address: example.com:443}
  tags: {kuma.io/service: ext-legacy}
---
apiVersion: kuma.io/v1alpha1
kind: VirtualOutbound
mesh: default
metadata: {name: vo-legacy, namespace: kuma-system}
spec:
  selectors: [{match: {kuma.io/service: "*"}}]
  conf:
    host: "{{.svc}}"
    port: "8080"
    parameters: [{name: svc, tagKey: kuma.io/service}]
EOF
```

### 4b. Meshes — inline legacy settings + a clean Exclusive mesh

Exercises `checkMeshSettings` (BUG-1: these blockers do NOT fire — the API inlines the
spec, no `spec` key). `clean` exercises the false-positive "not Exclusive".

```bash
kubectl apply -f - <<'EOF'
apiVersion: kuma.io/v1alpha1
kind: Mesh
metadata: {name: legacy}
spec:
  mtls:
    enabledBackend: ca-1
    backends: [{name: ca-1, type: builtin}]
  metrics:
    enabledBackend: prom-1
    backends: [{name: prom-1, type: prometheus}]
  tracing:
    defaultBackend: zipkin-1
    backends:
      - {name: zipkin-1, type: zipkin, conf: {url: http://zipkin:9411/api/v2/spans}}
  logging:
    defaultBackend: file-1
    backends: [{name: file-1, type: file, conf: {path: /tmp/access.log}}]
  constraints:
    dataplaneProxy:
      requirements: [{tags: {kuma.io/service: "*"}}]
  routing:
    localityAwareLoadBalancing: true
    zoneEgress: true
    defaultForbidMeshExternalServiceAccess: true
  networking:
    outbound: {passthrough: false}
---
apiVersion: kuma.io/v1alpha1
kind: Mesh
metadata: {name: clean}
spec:
  meshServices: {mode: Exclusive}
EOF
```

### 4c. New targetRef policies — `from` + bad targetRef kind

Exercises `checkNewPolicies` (these DO fire — new policies carry a `spec` envelope).

```bash
kubectl apply -f - <<'EOF'
apiVersion: kuma.io/v1alpha1
kind: MeshTrafficPermission
metadata:
  name: mtp-from-legacy
  namespace: kuma-system
  labels: {kuma.io/mesh: legacy}
spec:
  targetRef: {kind: Mesh}
  from:
    - targetRef: {kind: MeshSubset, tags: {kuma.io/service: web}}
      default: {action: Allow}
---
apiVersion: kuma.io/v1alpha1
kind: MeshHTTPRoute
metadata:
  name: mhr-badtargetref
  namespace: kuma-system
  labels: {kuma.io/mesh: legacy}
spec:
  targetRef: {kind: MeshService, name: web}
  to:
    - targetRef: {kind: MeshService, name: backend}
      rules: [{matches: [{path: {type: PathPrefix, value: /}}]}]
EOF
```

### 4d. Real Dataplane with `reachableServices`

Exercises `checkDataplanes` (BUG-2: blocker does NOT fire — `networking` inlined).

```bash
kubectl create namespace k3pf-test
kubectl label namespace k3pf-test kuma.io/sidecar-injection=enabled --overwrite

kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: reachable-app, namespace: k3pf-test}
spec:
  replicas: 1
  selector: {matchLabels: {app: reachable-app}}
  template:
    metadata:
      labels: {app: reachable-app}
      annotations:
        kuma.io/transparent-proxying-reachable-services: "backend_k3pf-test_svc_80"
    spec:
      containers:
        - name: app
          image: nginx:stable-alpine
          ports: [{containerPort: 80}]
EOF

kubectl rollout status deploy/reachable-app -n k3pf-test
```

---

## 5. Run the audit

```bash
# All meshes
/tmp/kuma3-preflight --address http://localhost:5681 --timeout 30s --output /tmp/k3pf-all.md
echo "exit=$?"; cat /tmp/k3pf-all.md

# Single mesh / edge cases
/tmp/kuma3-preflight --address http://localhost:5681 --mesh clean --timeout 15s   # BUG-1 false positive
/tmp/kuma3-preflight --address http://localhost:5681 --mesh ghost --timeout 15s   # exit 2, FAILED stamp
```

### Quick API-shape checks (root-cause evidence)

```bash
# Core resources: NO "spec" key (fields inlined) — this is what breaks the tool
curl -s http://localhost:5681/meshes/legacy | python3 -m json.tool
curl -s http://localhost:5681/meshes/default/dataplanes | \
  python3 -c "import sys,json;i=json.load(sys.stdin)['items'][0];print('has spec:', 'spec' in i, '| keys:', sorted(i.keys()))"

# New policies: HAVE a "spec" key
curl -s http://localhost:5681/meshes/default/meshtimeouts | \
  python3 -c "import sys,json;i=json.load(sys.stdin)['items'][0];print('has spec:', 'spec' in i)"
```

---

## 6. Expected results (current/hardened build)

The four bugs the original run found (BUG-1 inlined Mesh spec, BUG-2 inlined Dataplane
spec, BUG-3 unmarked system defaults, BUG-4 dropped path prefix) are fixed. Against the
current binary:

| Check family | Fires on real CP? | Notes |
|---|---|---|
| Removed legacy resources | ✅ yes | presence-counted, no spec parse |
| New-policy `from`/targetRef/`to`/proxyTypes | ✅ yes | new policies have `spec` envelope |
| Mesh inline settings (mTLS/metrics/…) | ✅ yes | `specBytes()` falls back to the whole object |
| `meshServices.mode` Exclusive | ✅ yes | `clean` correctly NOT flagged |
| Dataplane reachableServices / gateway / probes | ✅ yes | `probes` is Universal-only (see §7) |
| OTel `endpoint`, LB hashPolicies/SourceIP, healthyPanicThreshold, RFC-1035 names | ✅ yes | warnings |
| CP `policy-role: system` defaults | ✅ flagged + marked | header `Includes N CP-managed…` (**K8s only** — see §7) |
| Control-plane config (`GET /config`) | ✅ yes | `checkControlPlaneConfig`: blockers global-on-k8s / autoReachableServices / eBPF; warnings unified-naming / inbound-tags / deltaXds / KDS-watchdog / sidecar-containers off. Injector + global checks gated on `environment: kubernetes`. 404 → coverage gap. Mode stamped on the report from `/config`. |
| Multizone global fan-out | ✅ yes | Against `mode: global`, the data-plane config checks run **per zone** from `GET /zones+insights` (`ZoneInsight.subscriptions[].config`, the zone's own sanitized config shipped over KDS) — examples read `zone <name>: …`. Global keeps only the global-on-k8s blocker; a zone with no reported config (or `/zones+insights` 404) → coverage gap; no zones → info. A directly-connected zone/standalone CP is unchanged (audited from its own `/config`). |
| Dataplane version compatibility | ✅ yes | `checkDataplaneVersions` from `/dataplanes+insights`: warns on proxies with `kumaCpCompatible: false`. (preview/dev kuma-dp is bypassed by the CP → no warning on the preview fixture) |
| Dataplane per-proxy metrics override | ✅ yes | `checkDataplanes` flags non-empty `spec.metrics` (k8s: translated from `prometheus.metrics.kuma.io/*` pod annotations) → MeshMetric |
| Envoy DNS filter (`--inspect-dataplanes N`) | ⚙️ opt-in | `checkDataplaneEnvoyConfig` fetches up to N config dumps; warns on `envoy.filters.udp.dns_filter`. Off by default (expensive per-proxy fetch) |

---

## 7. Universal (no Kubernetes) setup

Universal is the only environment that can exercise the Dataplane `spec.probes` check
(on K8s, probes are pod-derived and intentionally skipped). It also surfaces a CP
behavior difference. No cluster needed — run the CP binary with an in-memory store.

```bash
# Build (or reuse) the local binaries
make build/kuma-cp build/kumactl
CP=build/artifacts-$(go env GOOS)-$(go env GOARCH)/kuma-cp/kuma-cp
K=build/artifacts-$(go env GOOS)-$(go env GOARCH)/kumactl/kumactl

# Free :5681 if a k3d port-forward holds it, then run a standalone zone CP in memory
pkill -f "port-forward.*5681" 2>/dev/null
KUMA_STORE_TYPE=memory KUMA_MODE=zone KUMA_DNS_SERVER_PORT=15653 \
  nohup "$CP" run --log-level=info >/tmp/uni-cp.log 2>&1 &
sleep 2; curl -s http://localhost:5681/   # expect product=Kuma

$K config control-planes add --name uni --address http://localhost:5681 --overwrite
```

Fixtures use the **universal resource format** (`type:`/`name:` at the top level;
legacy resources are flat, new policies nest under `spec:`). Apply the Mesh fixtures
(§4b but as `type: Mesh` / inline fields), the legacy resources (§4a as `type: …`), the
new policies (§4c), and a **Universal Dataplane carrying both `reachableServices` and a
`probes` section** (the K8s fixture cannot express a standalone Dataplane):

```bash
$K apply -f - <<'EOF'
type: Dataplane
mesh: default
name: dp-uni
networking:
  address: 127.0.0.1
  inbound: [{port: 8080, tags: {kuma.io/service: web}}]
  transparentProxying:
    redirectPortInbound: 15006
    redirectPortOutbound: 15001
    reachableServices: [backend]
probes:
  port: 9000
  endpoints: [{inboundPath: /health, inboundPort: 8080, path: /health}]
EOF

/tmp/kuma3-preflight --address http://localhost:5681 --output /tmp/uni-all.md; echo "exit=$?"
```

**Universal vs Kubernetes differences (verified):**
- Mesh and Dataplane specs are inlined (no `spec` key) — identical to K8s; all
  inline-spec checks fire.
- `Dataplane has a probes section` fires here, not on K8s.
- The CP's auto-generated default policies (`mesh-timeout-all-<mesh>`, …) **do not carry
  the `kuma.io/policy-role: system` label** on Universal (K8s sets it). They are still
  flagged as blockers, but **without** the `(system — CP-managed)` marker and **without**
  the `Includes N CP-managed` header. Not a tool bug — the tool reflects the label the CP
  provides.

---

## 8. Teardown

```bash
# Kubernetes
k3d cluster delete kuma-1
pkill -f "port-forward.*5681"

# Universal
pkill -f "kuma-cp run"
```

_Source of truth for 3.0 deprecations: `docs/deprecated-features.md`.
Test plan: `test-plan.md`. Results: `test-results.md`._
