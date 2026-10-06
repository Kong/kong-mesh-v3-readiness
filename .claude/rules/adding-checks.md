# Adding / changing a deprecation check

Checks live in `preflight/audit.go`. Add the check **and a test**; docs
(`docs/deprecated-features.md`) and `examples/` can be updated separately.

Pick the site by check shape:

- **Removed mesh-scoped resource (always a blocker):** append to `legacyMeshScoped`
  (shape `{wsPath, kind, replacement, doc, policy}` — exported to importers as
  `preflight.RemovedKinds()`); `checkLegacyResources` lists + flags it automatically. Set
  `policy: true` for a classic Kuma 1.x *policy* type so it renders under the Policies group
  (`categoryRemovedPolicy`); leave it false for a networking/gateway resource, which stays
  under Removed resources.
- **New targetRef policy to scan:** add its workspace path to `newPolicyPaths` in
  `preflight/audit.go` (or to `enterprisePolicyPaths` for a Kong Mesh-only policy, which is
  listed with `listIfServed` so an OSS Kuma 404 is not a coverage gap).
- **Removed Kong Mesh (enterprise) policy:** append to `removedEnterprisePolicies`;
  `checkRemovedEnterprisePolicies` lists it with `listIfServed`. Every removed kind also feeds
  `removedKindNames()` (AccessRole/AccessAudit `types[]`), together with `legacyMeshScoped` and
  `removedCoreKinds`.
- **Deprecated/relocated field in a policy spec:** add/extend a `case` in `checkPolicyFields`
  (`preflight/audit.go`, switch on `it.Type`). Unmarshal only the fields you inspect into a
  local anonymous struct; on unmarshal error `return` (already counted as a parse error
  upstream). Field deprecations are **blockers**. The tool emits two severities in practice —
  `blocker` (gates CI) and `info` (non-actionable counts). The `warning` tier still
  exists in the model but no check produces one; prefer `blocker` for anything
  actionable.
- **Mesh object setting:** extend `checkMeshSettings` (`preflight/audit.go`, decode into
  `meshSpec`).
- **Dataplane / zone-proxy / resource-name check:** extend the matching `check*` method.

Record findings with `a.rep.add(sev, category, title, detail, example)`
(`preflight/report.go`) — identical `(severity, category, title)` tuples merge and
accumulate examples (capped at `preflight.ExampleCap` = 10). Build the example string
with the helpers in `preflight/audit.go`: `a.ref(it)` for a flagged resource (its KRI,
the identifier Kuma 3.0 addresses it by, tagged `(system — CP-managed, update before
3.0)` for `policy-role: system` resources); `qualified(it)`/`qualifiedNote(it, note)`
where system-tagging doesn't apply; a plain string for control-plane-wide free text;
`zoneRef(zone)` for per-zone config. A type without a 3.0 KRI (removed kinds, names
containing `_`) falls back to the legacy `mesh/name [zone:z]` display string — don't
hand-build KRI strings; `qualified` owns the fallback.

Then add a case to `sampleReport()` (`preflight/render_test.go`) / golden assertions. To
cover the check end-to-end (CP API → JSON), add a fixture under
`preflight/testdata/golden/kitchen-sink/responses/<wsPath>.json` that triggers it (or a new
scenario dir) and run `go test ./preflight/... -run TestGoldenReports -update` to refresh
the reference JSON — the mock CP defaults any unlisted collection to an empty list, and
`404.txt` forces coverage gaps. Review the golden diff before committing.

New manual (non-CP-detectable) items go in the `manualChecks` slice in `preflight/audit.go`.

## Severity — choose deliberately

**Default to `blocker` for anything actionable** — deprecations, relocations and
should-fix items are blockers. `info` is reserved for non-actionable counts. Severity
never changes the exit code (findings live in the report); `info` leaves a fully-observed
run `clean`.
The `warning` tier still exists in the severity enum, but no check emits one and the
HTML report no longer renders a warnings section — do not add new warnings.

| Severity  | Meaning | Use for |
|-----------|---------|---------|
| `blocker` | Anything the operator must act on before 3.0; gates CI (exit 1) | removed resources, inline mTLS/metrics/tracing/logging on Mesh, `routing.*`, `reachableServices`, policy `from`, non-Mesh/Dataplane top-level `targetRef.kind`, **`meshServices.mode != Exclusive`**, CP-config **unified naming off** / **inbound tags still enabled** / global-on-k8s / autoReachableServices / eBPF; `proxyTypes`, removed `to` kinds (subset/selector + MeshGateway; `Mesh`/`Mesh*Service`/`MeshHTTPRoute` stay valid), OTel `endpoint`, relocated fields, non-RFC-1035 names, Universal Dataplane `probes`, **k8s pods with virtual probes enabled** (k8s `spec.probes`), **inbound protocol only in the `kuma.io/protocol` tag** (non-`tcp`) or **Kafka inbound protocol** (field or tag), **Dataplane advertising `feature-readiness-unix-socket`**, **Dataplane whose non-empty features omit `feature-delta-grpc`, `feature-reuse-port`/`feature-strict-inbound-ports` or `feature-otel-via-kuma-dp`**, **Kubernetes sidecar governed by a CNI control plane whose features omit `feature-transparent-proxy-in-dataplane-metadata`** (`checkDataplaneFeatures`), **CNI control plane without `transparentProxyConfigMap`**, **Universal outbound MeshService `backendRef` by `name`**, **MeshHTTPRoute rule with `backendRefs: []`**, **zone-origin MeshExternalService**, per-proxy `spec.metrics`, version-incompatible dataplanes, **kuma-dp older than 2.14** (with the CP/zone version findings it forms the `upgrade_path` group, rendered first), **Dataplane not yet on unified resource naming** (advertised features omit `feature-unified-resource-naming` — CP flag off, or on but the proxy has not reconnected; `checkDataplaneVersions` reads `dataplaneInsight.metadata.features`), **transparent-proxy Dataplane on the legacy CoreDNS** (non-empty advertised features omit `feature-embedded-dns`, or a `coredns` dependency is reported), **control plane (or any connected zone CP) not on the latest 2.14 patch**, CP-config deltaXds/KDS-watchdog/sidecar-containers off, **CP-config startup breaks** (`apiServer.authn.type: adminClientCerts`, `bootstrapServer.params.readinessPort: 0`) and silently dropped settings (`apiServer.auth.clientCertsDir`, `experimental.exposeZoneProxyMetrics`, `store.cache.enabled: false`, custom `experimental.kdsEventBasedWatchdog` timing, `metrics.mesh.{min,max}ResyncTimeout` — `addDroppedSettingFindings`, every mode incl. global), **global `dpServer.authn.zoneProxy.zoneToken.enableIssuer: false`** (`addZoneTokenIssuerFinding`, global only), **Universal `dpServer.authn.zoneProxy.type: none` with a non-`none` dpProxy type**, **`experimental.kubeOutboundsAsVIPs: false` on Kubernetes**, **MADS still enabled on a Kubernetes CP** (`monitoringAssignmentServer.enabled`, nil reads as the `true` default), unparseable specs; **Universal Dataplane missing the `kuma.io/workload` label**; **targetRef/route backendRef by `name`/`namespace`/`mesh`** (no `labels`); **route backendRef kind** other than MeshService/MeshExternalService/MeshMultiZoneService; **MeshPassthrough `Domain` match without `port`**; **MeshService `dataplaneTags` / `ServiceTag` identity / unsupported `appProtocol`** (`checkServiceResources`); **MeshExternalService old DataSource TLS shape**; **producer policy whose `to[]` items are not pinned by exactly display-name + own namespace + own zone**; **mesh with MeshExternalServices but no MeshIdentity** (`checkExternalServiceIdentity`, via `listServed` so an unreadable list is a gap); **reserved `kuma.io/`/`k8s.kuma.io/` label outside the 3.0 registry** on a user-authored resource, or **a selector keyed on one** (`checkReservedLabels`, `addSelectorOnRemovedLabel`; keep `knownReservedLabels` in sync with upstream `registry.go`); **`reachableBackends` ref without `labels`** (a 2.x `name`/`namespace` ref; 3.0 requires labels, k8s + Universal); **`ZoneIngress`/`ZoneEgress` present** (separate resources replaced by the unified Zone Proxy); **`MeshGlobalRateLimit` present** (enterprise policy removed in 3.0, no replacement — `checkRemovedEnterprisePolicies`, listed via `listIfServed` so an OSS-Kuma 404 is not a coverage gap); **legacy `OPAPolicy` present** (same list); **MeshOPA flat DataSource** (`agentConfig`/`appendPolicies[].rego` without `type` - rewrite before the global upgrade, a 3.0 global breaks either shape on 2.14 zones); **AccessRole qualifiers 3.0 rejects** (`when[].targetRef.kind` not Mesh/Dataplane, `when[].from`, `when[].to.targetRef.kind` subset/MeshGateway, `when[].to.targetRef` non-Mesh kind without `name`, `sources`/`destinations`/`selectors`) and **AccessRole/AccessAudit `types[]` naming a removed kind** (`checkAccessControl`, `removedKindNames`); **AccessRole granting `GENERATE_DATAPLANE_TOKEN` without `VIEW_CONTROL_PLANE_METADATA`** (`checkConfigAccess`: 3.0 gates `/config` on the latter); the outbound-deny defaults (`checkOutboundDefaults` / `checkPassthroughDefault`, see below; both block only proxies whose governing CP leaves `defaults.restrictOutbound` unset; an explicit `false` or `true` drops both to `info`) |
| `info`    | Informational, no action mandated | sampled-dataplane inspection coverage, no-zones-connected coverage note, proxies without `reachableBackends` or MeshPassthrough selection on a CP whose `defaults.restrictOutbound` is set, AccessRole qualifier matching a `targetRef` by `name` (3.0 narrows it to a display-name label match; the 2.14 qualifier has no `labels` to rewrite it with before upgrading), legacy DNS VIP settings 3.0 ignores without effect (`dnsServer.CIDR`/`serviceVipEnabled`, `useTagFirstVirtualOutboundModel`), Universal Dataplane `transparentProxying.ipFamilyMode`/`redirectPort*` (still honored on 3.0, removed in 3.1), AccessRoleBinding naming `mesh-system:unauthenticated`/`system:unauthenticated` (3.0 keeps an existing binding unchanged) |

## Absence-triggered checks

A check that fires on a resource having *nothing* (the 3.0 outbound-deny
defaults: `checkOutboundDefaults`, `checkPassthroughDefault`) would otherwise hit
almost every resource in an estate. Four extra obligations:

- **Summary form.** Tally affected/eligible, then emit one `collector.addSummary` finding whose detail states the "N of M" ratio — not one `addDoc` per resource.
- **Read with `listCollObserved`** and return early when the collection was not observed. "Not observed" is not "absent".
- **Read policy selection from the CP** (`_resources/dataplanes`) instead of reimplementing the matcher; an unreadable selection is a coverage gap for that mesh.
- **Carry a remediation**, split per environment where the fix differs (Pod annotation on Kubernetes, Dataplane field on Universal). A blocker firing on everything with nowhere to go is noise.
