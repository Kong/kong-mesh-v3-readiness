# Adding / changing a deprecation check

Checks live in `audit.go`. Add the check **and a test**; docs
(`docs/deprecated-features.md`) and `examples/` can be updated separately.

Pick the site by check shape:

- **Removed mesh-scoped resource (always a blocker):** append to `legacyMeshScoped`
  (`audit.go:20`, shape `{wsPath, kind, replacement}`); `checkLegacyResources`
  (`audit.go:214`) lists + flags it automatically.
- **New targetRef policy to scan:** add its workspace path to `newPolicyPaths` (`audit.go:39`).
- **Deprecated/relocated field in a policy spec:** add/extend a `case` in `checkPolicyFields`
  (`audit.go:273`, switch on `it.Type`). Unmarshal only the fields you inspect into a local
  anonymous struct; on unmarshal error `return` (already counted as a parse error upstream).
  Field deprecations are **blockers** — the tool has three severities: `blocker`, `warning` and `info`.
- **Mesh object setting:** extend `checkMeshSettings` (`audit.go:157`, decode into `meshSpec`).
- **Dataplane / zone-proxy / resource-name check:** extend the matching `check*` method.

Record findings with `a.rep.add(sev, category, title, detail, exampleRef)` (`report.go:50`) —
identical `(severity, category, title)` tuples merge and accumulate example refs (capped at
`exampleCap` = 10, `audit.go:52`). Use `a.ref(it)` for the example ref so CP-managed
(`policy-role: system`) resources are tagged and counted; use `qualified(it)` only where
system-tagging doesn't apply.

Then add a case to `sampleReport()` (`render_test.go:11`) / golden assertions. To cover
the check end-to-end (CP API → JSON), add a fixture under
`testdata/golden/kitchen-sink/responses/<wsPath>.json` that triggers it (or a new scenario
dir) and run `go test -run TestGoldenReports -update` to refresh the reference JSON — the
mock CP defaults any unlisted collection to an empty list, and `404.txt` forces coverage
gaps. Review the golden diff before committing.

New manual (non-CP-detectable) items go in the `manualChecks` slice in `audit.go`.

## Severity — choose deliberately

Three severities. **Default to `blocker` for anything actionable** — deprecations,
relocations and should-fix items are blockers. `warning` is the narrow exception: an item
the operator should review but that does **not** break the 3.0 upgrade (the default is valid,
just possibly not what they want), so it must not gate CI. `info` is reserved for
non-actionable counts. Only `blocker` changes the exit code; `warning` and `info` leave a
fully-observed run `clean` (exit 0).

| Severity  | Meaning | Use for |
|-----------|---------|---------|
| `blocker` | Anything the operator must act on before 3.0; gates CI (exit 1) | removed resources, inline mTLS/metrics/tracing/logging on Mesh, `routing.*`, `reachableServices`, gateway-in-Dataplane, policy `from`, non-Mesh/Dataplane top-level `targetRef.kind`, **`meshServices.mode != Exclusive`**, CP-config **unified naming off** / **inbound tags still enabled** / global-on-k8s / autoReachableServices / eBPF; plus the former warnings: `proxyTypes`, removed `to` kinds (subset/selector + MeshGateway; `Mesh`/`Mesh*Service`/`MeshHTTPRoute` stay valid), OTel `endpoint`, relocated fields, non-RFC-1035 names, Universal Dataplane `probes`, per-proxy `spec.metrics`, version-incompatible dataplanes, **control plane (or any connected zone CP) not on the latest 2.14 patch**, CP-config deltaXds/KDS-watchdog/sidecar-containers off, unparseable specs; **Universal Dataplane missing the `kuma.io/workload` label**; **`ZoneIngress`/`ZoneEgress` present** (separate resources replaced by the unified Zone Proxy); **`MeshGlobalRateLimit` present** (enterprise policy removed in 3.0, no replacement — `checkRemovedEnterprisePolicies`, listed via `listIfServed` so an OSS-Kuma 404 is not a coverage gap) |
| `warning` | Actionable advisory that does not break the upgrade; does NOT gate CI | k8s **`workloadLabels` unset** (kuma.io/workload falls back to the pod ServiceAccount — fine only if ServiceAccounts are distinct per workload) |
| `info`    | Informational, no action mandated | sampled-dataplane inspection coverage, no-zones-connected coverage note |
