# Manual Test Plan — `kuma3-preflight`

Produced via the three-persona method (Bach / Kaner / Hendrickson), drafted in parallel and merged. Manual verification only — these are run by a human (or a thin stub-server harness), not automated here.

## Scope

`cmd/kuma3-preflight` (`main.go`, `client.go`, `audit.go`, `report.go`) — a stdlib-only Go CLI that audits a running Kuma control plane over its REST API (default `http://localhost:5681`) and emits a JSON or self-contained HTML pre-upgrade report for Kuma 3.0 (default HTML; Markdown is `--classify`-only). Exit codes: `0` clean · `1` blockers found · `2` operational error · `3` audit inconclusive (a collection could not be read, or a resource spec failed to parse). Flags: `--address`, `--token`, `--mesh`, `--output`, `--timeout`.

Most cases use a **local stub HTTP server** that mimics the CP REST API (the cheapest way to drive edge responses); a few want a real Kuma 2.x CP.

> ⚠️ **Stub fidelity is mandatory.** A real Kuma CP serializes spec **two ways** (see `pkg/core/resources/model/rest/`): **core/legacy resources** (Mesh, Dataplane, TrafficPermission, ExternalService, …) inline their spec fields at the **top level with no `spec` key**; **new targetRef policies** (MeshTimeout, MeshHTTPRoute, …) nest under a `spec` envelope. A stub that wraps *everything* in `spec` will mask the BUG-1/BUG-2 class entirely (it did once — see TC-23). Every stub fixture MUST mirror the real encoding per resource type. Prefer a real CP for TC-15/TC-23.

## Pre-conditions

- Built binary: `go build -o /tmp/kuma3-preflight ./cmd/kuma3-preflight`
- A scriptable stub HTTP server (any language) able to: serve `GET /`, `GET /meshes`, the legacy/new collection paths, `/dataplanes`, `/zoneingresses`, `/zoneegresses`; control status codes, bodies, delays, `next` cursors, content-type — and serialize spec per the fidelity note above (inline for core/legacy/Dataplane, nested `spec` for new policies).
- For compatibility / serialization cases (TC-15, TC-23): a real Kuma 2.x CP (k3d setup: `docs/test-setup.md`).
- The 3.0 migration source of truth: `docs/deprecated-features.md`.

## Test cases

### A. Connectivity & CP identification

#### TC-1: Wrong endpoint returns HTTP 200 with a non-Kuma body → false green
**Setup:** Stub where `GET /` returns `200` with an HTML login page (or `{}`). All collections empty.
**Steps:**
1. Run `kuma3-preflight --address http://127.0.0.1:<port>`.
2. Inspect header, findings, exit code.
**Expected:** Pointing at a non-CP/wrong path is an operational error (exit 2): "could not identify a Kuma control plane".
**Oracle:** FAIL if it prints `Control plane: Kuma` (the default when `product` is empty), "Meshes scanned: all", 0 findings, ✅, exit 0. A preflight that green-lights a non-CP is worse than useless.
**Source:** Bach — Purpose oracle; wrong-endpoint error guessing.

#### TC-2: CP index 404 / connection refused / DNS failure
**Setup:** (a) `GET /` → 404; (b) `--address` to a closed port; (c) unresolvable host; (d) `http://` against an https-only CP and vice versa.
**Steps:** Run each; capture exit code + stderr.
**Expected:** Each fails fast, exit 2, with a *distinct* actionable message (not found / refused / DNS / TLS-protocol mismatch).
**Oracle:** PASS only if the four failure modes are distinguishable in stderr. FAIL if any yields exit 0 or a single vague "connection error".
**Source:** Hendrickson — Configuration Tour (scheme × reachability); Bach — World oracle.

### B. Authentication & token handling

#### TC-3: Token never leaks to stderr/report/file
**Setup:** (a) `--token SUPERSECRET` against a CP whose `GET /` returns `401` with body `{"error":"token SUPERSECRET rejected"}`; (b) a TLS handshake failure with token set.
**Steps:**
1. Run, capturing combined output: `kuma3-preflight ... --token SUPERSECRET 2>&1 | grep SUPERSECRET`.
2. Repeat writing to `--output r.md`; grep the file.
**Expected:** Token appears nowhere — not stderr, not the report, not error strings.
**Oracle:** `grep` must return empty. Note the real risk: `getJSON` echoes up to 512 bytes of the **response body** into the error; a CP that reflects the token in its 401 body would surface it. FAIL if the token (from header) ever shows, or a reflected-token body is printed unredacted.
**Source:** Bach — security/token-leakage; Comparable-products oracle.

#### TC-4: Empty vs invalid token semantics
**Setup:** CP requiring auth. Run with (a) `--token ""` (unset) and (b) a wrong token; CP returns 401.
**Steps:** Run each; capture exit code + message.
**Expected:** 401/403 → exit 2 with an authentication-specific message (`getJSON` now appends "authentication failed; check --token"), never a clean report. `--token ""` must not be sent as a valid empty credential that yields a misleading pass.
**Oracle:** FAIL if an auth-required CP with a bad/empty token produces exit 0/clean, or the message is a bare `status 401` with no auth hint.
**Source:** Hendrickson — Configuration Tour (auth combinatorics); Kaner — exit-code trust.

### C. Pagination & partial failure

#### TC-5: `next` cursor that never advances → infinite loop / hang
**Setup:** Stub returns, for a collection, a page whose `next` resolves to the *same* path+query it just served (cursor never advances).
**Steps:** Run with `--timeout 60s`; watch CPU, memory, wall-clock.
**Expected:** Tool detects a non-advancing/repeating cursor (or enforces a page cap) and bails quickly with exit 2.
**Oracle:** FAIL if it spins, accumulating duplicate items and growing memory, until the deadline fires at ~60s. (`client.go` has no visited-set and no page cap.)
**Source:** Bach — World oracle + Zero-One-Many ("many = ∞").

#### TC-6: Failure mid-pagination is not reported as complete
**Setup:** `/dataplanes` spans 3 pages; 40 dataplanes on later pages carry `reachableServices` (BLOCKER). Page 1 → 200; page 2 → 401 (or 500), or page 2 hangs past the timeout.
**Steps:** Run; capture exit code and whether the report includes only page-1 data.
**Expected:** Any non-200/404 (or timeout) *during* pagination aborts with exit 2 naming the collection/phase; the report does not present partial results as authoritative.
**Oracle:** FAIL if page-1 findings are emitted with exit 0/1 as if the whole fleet was scanned. Verify the error fires from *inside* the loop, not only on the first request.
**Source:** Kaner — reliability under partial failure; Hendrickson — paginating→stalled→abort transition.

#### TC-7: Overall `--timeout` is authoritative
**Setup:** Stub sleeps 20s on `GET /`. (a) `--timeout 5s`; (b) `--timeout 90s` with the server hanging indefinitely on `GET /meshes`.
**Steps:** Measure wall-clock to exit for each.
**Expected:** (a) aborts at ~5s, exit 2. (b) the user's 90s budget governs — not a hidden 30s per-request `http.Client.Timeout` firing first.
**Oracle:** FAIL if effective timeout is the min/max of two uncoordinated timers, making `--timeout` non-authoritative in either direction (it is documented as "Overall timeout for the audit").
**Source:** Bach — Claims oracle + Time coverage; Hendrickson — tiny-timeout tour.

### D. Mesh scoping (`--mesh`)

#### TC-8: `--mesh` naming a non-existent mesh
**Setup:** CP with meshes `default` (clean) and `payments` (inline mTLS → blocker). Run `--mesh payment` (typo) and `--mesh ghost`.
**Steps:** Run; capture exit code, stderr, and which paths are requested.
**Expected:** Auditing a mesh that resolves to nothing is exit 2 (or a loud, unmistakable warning) — never a clean exit 0. The header states which mesh was actually matched.
**Oracle:** FAIL if a typo'd/absent mesh yields an empty clean report + exit 0 — an operator reads that as "this mesh is upgrade-safe". The tool must not conflate "mesh empty" with "mesh absent".
**Source:** Kaner — consent + false negative from input mismatch; Hendrickson — Configuration Tour.

#### TC-9: `--mesh` with URL metacharacters / path traversal
**Setup:** Run with `--mesh "../../meshes/default/dataplanes"`, `--mesh "a b"` (space), `--mesh "default%3f"`.
**Steps:** Capture the exact request paths the stub receives.
**Expected:** The mesh segment is percent-escaped or validated before being concatenated into the URL path.
**Oracle:** FAIL if the stub receives a traversed path (`/meshes/../../...`), or a space/`?` corrupts the path-vs-query split, or produces a confusing exit-2 message. (`scopedPath` builds the path by raw string concatenation; `getJSON` splits on the first `?`.)
**Source:** Bach — injection/garbage input; Familiar oracle.

#### TC-10: Cross-mesh attribution — path scope vs payload `mesh` field
**Setup:** A mesh-scoped collection listed unscoped (`/<type>`, all meshes) returns items whose `mesh` fields are `default`, `prod`, `prod`. Run (a) unscoped and (b) `--mesh prod`.
**Steps:** Compare per-mesh finding attribution and counts between runs.
**Expected:** Unscoped attributes each item to its own `mesh` field; `--mesh prod` counts prod items only, excludes default; no item double-counted or mis-attributed.
**Oracle:** FAIL if scoping disagrees with the item's self-reported `mesh`, or items are attributed by request path instead of payload.
**Source:** Hendrickson — Data Tour (identity: path-scope vs payload-scope).

### E. Detection correctness (the core value)

#### TC-11: 404 on a collection — "absent" vs "not audited" must be distinguishable
**Setup:** Real or stub CP with 50 `TrafficPermission`s, but a proxy returns 404 for the `traffic-permissions` path only (auth rule, moved endpoint, or `--address` subpath typo). Compare against a genuinely empty CP.
**Steps:** Run both; diff the reports and exit codes.
**Expected:** The operator can tell `traffic-permissions` was not actually audited: the 404 run emits a `## Coverage gaps` section, a ⚠️ verdict, and **exit 3** (inconclusive); the empty run is ✅ exit 0.
**Oracle:** FAIL if the 50-policies-behind-404 run and the genuinely-empty run produce byte-identical clean reports, or both exit 0. The audit's promise ("nothing blocks your upgrade") must not be asserted on evidence it never gathered. **This is the highest-harm false negative.**
**Source:** Kaner — data integrity / false negative.

#### TC-12: Malformed resource spec is not silently skipped
**Setup:** Stub returns a policy whose `spec` is structurally valid JSON but a typed field is wrong (e.g. a `*bool` sent as `"true"`, or `from` sent as an object not array), so `json.Unmarshal` into the typed struct errors.
**Steps:** Run; check whether that policy is flagged or silently dropped.
**Expected:** A resource the tool fails to parse is surfaced under `Unparseable resources` (warning), counted in the header, and forces **exit 3** (inconclusive) — never silently omitted.
**Oracle:** FAIL if the unparseable policy disappears from the report, or the run exits 0 despite an unparseable resource (it could hide a blocker).
**Source:** Bach — Purpose oracle (silent false-negative on a gate); garbage-data coverage.

#### TC-13: Presence-based settings detection across CP versions
**Setup:** Two CP patch levels. Author the *same* mesh YAML on both; one serializes `networking.outbound.passthrough` (or `routing.*`) explicitly, the other omits it / emits `{}`. (`passthrough` detection is presence-based; `hasJSON` treats `null/{}/[]` as empty.)
**Steps:** Apply identical intent to both; run preflight against each; capture the serialized JSON as evidence.
**Expected:** Identical operator intent → identical findings. Detection keys on the field **value**, not object presence: `passthrough: true` → blocker; `outbound: {}` or omitted → no blocker (the `*bool` is nil). An explicit `passthrough: false` is still flagged (the field is removed regardless of value — intentional).
**Oracle:** FAIL if `networking.outbound: {}` produces a passthrough blocker (the old presence-based false positive), or the two CP versions disagree for the same authored config.
**Source:** Kaner — compatibility; oracle reads serialization artifact, not intent.

#### TC-14: Every BLOCKER is genuinely a 3.0 break (no cry-wolf)
**Setup:** Apply current-valid configs that the tool flags: a new policy using `from`, a top-level `targetRef.kind` ≠ Mesh/Dataplane, `to[]` ≠ Mesh*Service, `proxyTypes`.
**Steps:** For each flagged construct, cross-check `docs/deprecated-features.md` (and 3.0 migration docs) that it genuinely breaks/changes in 3.0, per policy type.
**Expected:** No false positives; each blocker maps to a real, documented 3.0 change. CP-managed default policies (`kuma.io/policy-role: system`, e.g. `mesh-timeout-all-<mesh>`) use the same deprecated constructs and **are intentionally flagged** — marked `(system — CP-managed, update before 3.0)` and counted in the header — because the operator must update them before upgrading. This is decided behavior, not cry-wolf (see TC-24).
**Oracle:** FAIL if `from` (or any construct) is flagged where 3.0 retains it for some policy types, OR if system policies are silently skipped (an operator would miss config they must update). The 3.0 spec is the authority; the tester must cite it.
**Source:** Kaner — quality-is-value / false positive; external-authority oracle.

#### TC-15: Happy-path coverage — a fully legacy mesh and a fully clean mesh
**Setup:** (a) A mesh exercising every category: ≥1 of each legacy resource, inline mTLS + each `routing.*` + metrics/tracing/logging + constraints, a `from` policy, a bad targetRef, a dataplane with `reachableServices` and one with `networking.gateway`, plus ZoneIngress/Egress. (b) A mesh in `meshServices.mode: Exclusive` with only new policies, no legacy anything.
**Steps:** Run against each.
**Expected:** (a) Every check fires with correct severity; exit 1. (b) No blockers, only the manual-checks list and INFO; exit 0, ✅.
**Oracle:** FAIL if any expected finding is missing/mis-severitied in (a), or any false blocker appears in (b). This is the primary feature tour.
**Source:** Hendrickson — Feature/Data Tour; merge.

### F. Report rendering & determinism

#### TC-16: Merge across many meshes + example cap boundary
**Setup:** 50 meshes each producing the identical finding `(severity,category,title)`; collectively 1500 example resources for it. Separately, exactly 10 and exactly 11 examples for a finding.
**Steps:** Run; inspect the merged finding row and the "(+N more)" line.
**Expected:** One merged row; `count` = full total (e.g. 1500); examples ≤ 10; suffix `(+1490 more)`. At exactly 10 → no "+0 more"; at 11 → "(+1 more)".
**Oracle:** FAIL if duplicates aren't merged, count is wrong, examples exceed 10, or the residual count is wrong/absent.
**Source:** Bach — Zero-One-Many at the cap boundary; Kaner — legibility; Hendrickson — Data Tour merge.

#### TC-17: A lone blocker is not buried under a dominant category
**Setup:** 60 `TrafficRoute` blockers + a single dataplane `networking.gateway` blocker. Hand the rendered report to a second operator.
**Steps:** Ask them to list *every distinct thing they must fix* and the true per-class counts.
**Expected:** They enumerate both classes and the real counts even with examples capped.
**Oracle:** FAIL if they under-count routes (cap shown without "10 of 60" total) or miss the lone gateway blocker among 60 lines. The report — not the exit code — is the deliverable.
**Source:** Kaner — usability / legibility.

#### TC-18: Determinism across repeated runs
**Setup:** Frozen stub (stable multi-mesh dataset with merges and over-cap examples).
**Steps:** Run 10× to separate files; `diff` all pairs.
**Expected:** Byte-identical reports: section order, finding order within a section, example order, counts.
**Oracle:** FAIL on any run-to-run reordering (e.g. Go map-iteration nondeterminism). A pre-upgrade report is an artifact operators diff and attach to tickets.
**Source:** Hendrickson — Soak/Determinism Tour.

### G. Output handling & robustness

#### TC-19: `--output` overwrite, symlink, unwritable dir, missing dir
**Setup:** (a) `--output` to an existing non-empty file; (b) to a symlink pointing at a sensitive file; (c) to `/etc/hosts` (no perms); (d) to `/nonexistent-dir/r.md`.
**Steps:** Run each; check exit code, stderr, and the target's final content/permissions.
**Expected:** Perms/missing-dir failures → exit 2, clear message, target untouched. Existing file → predictable overwrite (ideally with awareness); symlink handling shouldn't clobber an unrelated sensitive file.
**Oracle:** FAIL if a non-empty existing file is silently truncated with no signal, or a symlink is followed to clobber another file (`os.WriteFile(..., 0o600)` truncates + follows symlinks).
**Source:** Bach — User-expectations + Operations coverage.

#### TC-20: Output file consistency with exit code (stale/partial artifact)
**Setup:** Prior successful run left a clean report at `--output /reports/preflight.md`. This run hits a non-200 on the second collection (exit 2). Then SIGINT a long run mid-pagination writing to a new path.
**Steps:** After the failing run, inspect exit code AND the file. After SIGINT, inspect the file.
**Expected:** On exit 2, the file is not left as a complete-looking clean report (write atomically only on a complete run, or stamp an error). On SIGINT, no half-written report (all-or-nothing).
**Oracle:** FAIL if a CI artifact step publishes a stale/partial clean-looking report from a failed/interrupted run — a dashboard reads the file, not `$?`, and concludes "upgrade-safe".
**Source:** Kaner — supportability / data integrity; Hendrickson — Interruption Tour.

#### TC-21: Adversarial HTTP bodies
**Setup:** Per collection in turn: (a) truncated JSON; (b) `Content-Type: text/html` + valid JSON; (c) a very large body (hundreds of MB) of items; (d) `Content-Encoding: gzip` header on a plaintext body; (e) duplicate JSON keys.
**Steps:** Run against each; observe exit code, memory (RSS), and whether one bad collection corrupts the whole audit.
**Expected:** Malformed → clear per-endpoint error (exit 2), bounded memory; wrong content-type tolerated (decode regardless); a huge body must not OOM the process; a single bad collection must not silently yield "0 findings, ✅".
**Oracle:** FAIL if RSS balloons (no `io.LimitReader` on the success decode path), or an error message leaks body/token, or a parse failure degrades to a misleading clean report.
**Source:** Bach — Data coverage + Goldilocks (way-too-large).

#### TC-22: The empty estate (0 meshes / 0 resources)
**Setup:** Stub: valid index, `GET /meshes` → `{items:[],next:null}`, all collections empty.
**Steps:** Run; capture stdout + exit code.
**Expected:** Clean report, exit 0, no panic; header reads `Meshes scanned: none` (NOT `all`).
**Oracle:** FAIL on any panic, exit 2, or `Meshes scanned: all` for an estate with 0 meshes.
**Source:** Hendrickson — Data Tour (smallest valid dataset).

#### TC-23: Inlined vs nested spec serialization (real-CP regression — BUG-1/BUG-2)
**Setup:** A CP (prefer real; else a fidelity-correct stub) where Mesh `legacy` inlines `mtls`/`metrics`/`tracing`/`logging`/`constraints`/`routing.*`/`networking.outbound.passthrough` at the **top level with no `spec` key**; a Dataplane inlines `networking.transparentProxying.reachableServices` and a `networking.gateway` section; a Mesh `clean` has `meshServices.mode: Exclusive`; new policies (MeshTimeout, MeshHTTPRoute) carry a nested `spec`.
**Steps:** Run the full audit; inspect every Mesh-settings and Dataplane blocker.
**Expected:** All 9 Mesh-settings blockers fire; `reachableServices` and `networking.gateway` blockers fire; `clean` is NOT flagged `meshServices.mode is not Exclusive`. New-policy checks (which read the nested `spec`) keep working.
**Oracle:** FAIL if any Mesh/Dataplane check produces zero findings against inlined data (the silent no-op that a `spec`-wrapping stub hides), or if Exclusive is reported as not-Exclusive. `resourceItem.specBytes()` must fall back to the whole object when there is no `spec` envelope.
**Source:** real-CP run; merge (root cause: dual REST serialization).

#### TC-24: CP-managed (system) policies are flagged and marked, not skipped
**Setup:** A pristine, untouched mesh — its CP-generated defaults (`mesh-timeout-all-<mesh>`, `mesh-circuit-breaker-all-<mesh>`, …) carry `kuma.io/policy-role: system` and use `from` / `to: Mesh` / `proxyTypes`. Add one user-authored policy with `from`.
**Steps:** Run; inspect blockers, the header, and example markers.
**Expected:** System policies ARE flagged (e.g. `from` → blocker), each example marked `(system — CP-managed, update before 3.0)`; header shows `Includes N CP-managed (policy-role: system) resource(s) — update these before upgrading`. The user policy is flagged unmarked.
**Oracle:** FAIL if system policies are silently skipped (operator would miss config they must update before v3), or if user policies are wrongly marked system, or if the marker/header is absent.
**Source:** merge (operator requirement: system policies must be updated before migrating).

#### TC-25: `--address` path prefix is honored (behind an ingress)
**Setup:** Stub serving the CP under a path prefix: `GET /kuma/`, `GET /kuma/meshes`, `GET /kuma/<collection>`. Run `--address http://127.0.0.1:<port>/kuma`. Log every request path the stub receives.
**Steps:** Run a full audit; capture the request paths.
**Expected:** Requests hit `/kuma/meshes`, `/kuma/dataplanes`, … (prefix preserved); pagination cursors are not double-prefixed. A wrong subpath now reaches the server and 404s → exit 2/3 rather than a false green.
**Oracle:** FAIL if any request drops the `/kuma` prefix (hits host root), or a server cursor already carrying `/kuma/...` gets it prepended twice.
**Source:** real-CP run (BUG-4).

#### TC-26: Exit-code matrix
**Setup:** Drive each terminal state: clean Exclusive mesh; a mesh with a blocker; an unreachable CP; a 404'd collection; an unparseable resource.
**Steps:** Run each; record `$?`.
**Expected:** `0` clean · `1` blockers · `2` operational error (unreachable / bad flag / write failure) · `3` inconclusive (coverage gap OR unparseable). Blockers (1) take precedence over inconclusive (3).
**Oracle:** FAIL if any state maps to the wrong code — especially a 404'd collection or unparseable resource yielding `0`, which a CI `$?` gate would read as success.
**Source:** merge; Kaner — exit-code trust for automation.

## Basic / smoke manual tests

Run these first — they confirm the tool works at all before the edge-case TCs. Fast, mostly against the real k3d CP from the setup runbook. Each is pass/fail by inspection.

| # | Action | Expected |
|---|--------|----------|
| B-1 | `go build -o /tmp/kuma3-preflight ./cmd/kuma3-preflight` | Builds clean, no errors. |
| B-2 | `kuma3-preflight --help` (or `-h`) | Usage lists `--address --token --mesh --output --timeout` with defaults; exit 0. |
| B-3 | Port-forward CP, run with no flags (default `:5681`) | Connects, prints a report with the CP product/version header; exit 0/1/3 per content. |
| B-4 | Run against a **clean** Exclusive mesh only (`--mesh clean`) | No `meshServices.mode` warning, no operator-authored blockers; `Meshes scanned: clean`. Note: the CP auto-creates `mesh-timeout-all-clean` defaults using `from`, so expect 2 system-marked blockers + exit 1 (see TC-24). A true `✅`/exit 0 requires a mesh with no CP-managed defaults. |
| B-5 | Create one `TrafficPermission`, re-run | Exactly one `TrafficPermission (removed in 3.0)` blocker; exit 1. |
| B-6 | Create one `MeshTrafficPermission` with `from`, re-run | One `… uses from` blocker; exit 1. |
| B-7 | Apply inline `mtls` on a mesh, re-run | `Inline mTLS on Mesh` blocker fires (validates inlined-spec parsing). |
| B-8 | A mesh with `meshServices.mode` unset/Disabled | `meshServices.mode is not Exclusive` warning, current value shown. |
| B-9 | `--output /tmp/report.html` | stderr `report written to /tmp/report.html`; file contains the same HTML as stdout. |
| B-10 | `--mesh default` on the fixture cluster | Only `default`-mesh findings; header `Meshes scanned: default`. |
| B-11 | `--token bogus` against the CP | If CP requires auth → exit 2 with auth message; else normal report (token simply unused). |
| B-12 | Run twice, `diff` the two reports | Byte-identical (determinism). |
| B-13 | Point `--address` at a closed port | exit 2, `connection refused`; no panic, no partial report. |
| B-14 | Confirm the **manual checks** checklist renders | `## Manual checks` section present with the gateway-API / observability / DNS / inspect-API / pod-resources / Workload / HMAC-key / mesh-label / MES-zone-routing items. (Unified-naming, inbound-tags, deltaXds, autoReachableServices, global-on-k8s and eBPF moved to automated findings — see B-15.) |
| B-15 | Confirm the **Control plane configuration** findings render from `GET /config` | Findings category `Control plane configuration`; blockers for global-on-k8s / autoReachableServices / eBPF, warnings for unified-naming / inbound-tags / deltaXds / KDS-watchdog / sidecar-containers off. A CP that 404s `/config` yields a `/config` coverage gap, not a clean pass. The report's control-plane line shows the mode (read from `/config`). |
| B-15b | Confirm **global CP fans out to zones** for the data-plane config checks | Against a `mode: global` CP, the audit keeps the global-on-k8s blocker for the global itself but sources the injector/experimental checks from each zone's config in `GET /zones+insights` (`ZoneInsight.subscriptions[].config`), so examples read `zone <name>: …`. A zone that reported no config (or a 404 on `/zones+insights`) is a coverage gap; a global with no zones emits an info finding. A directly-connected zone/standalone CP is audited from its own `/config` (examples unqualified). |
| B-16 | Confirm **dataplane version** + **per-proxy metrics** findings | `Dataplane version` warning for any proxy with `kumaCpCompatible: false` (from `/dataplanes+insights`); `Dataplane metrics` warning for any Dataplane with `spec.metrics`. Preview/dev kuma-dp is reported compatible → no version warning. |
| B-17 | Confirm opt-in **Envoy DNS filter** inspection | With `--inspect-dataplanes N`, the audit fetches up to N config dumps and warns on `envoy.filters.udp.dns_filter`; reports `Inspected … X of M` when sampled. With the flag at `0` (default) no config dumps are fetched and no DNS-filter finding appears. |

#### TC-27: Full expected-findings verification on a running cluster
**Setup:** Provision the documented fixture cluster (`docs/test-setup.md`): on `default` — the 9 legacy resources, a `from` MeshTrafficPermission, a bad-targetRef MeshHTTPRoute, an injected Dataplane with `reachableServices`; Mesh `legacy` with all inline settings; Mesh `clean` in `meshServices.mode: Exclusive`. Note the CP also auto-creates `policy-role: system` defaults.
**Steps:** Run `kuma3-preflight --output actual.md`; compare every finding against the expected set below (no missing, no extra, correct severity, correct mesh attribution). Re-run `--mesh legacy`, `--mesh clean`, `--mesh default` and confirm scoping isolates the right findings.
**Expected (golden finding-set):**
- **Blockers** — each legacy resource on `default` (one per kind created); all 9 `legacy` Mesh-object settings (mTLS, metrics, tracing, logging, constraints, localityAwareLoadBalancing, routing.zoneEgress, defaultForbidMeshExternalServiceAccess, passthrough); the `from` MTP; the top-level `targetRef.kind=MeshService` MeshHTTPRoute; the Dataplane `reachableServices`; plus the CP system defaults' `from` (marked `(system …)`).
- **Warnings** — `meshServices.mode is not Exclusive` for `default` and `legacy` (NOT `clean`); `to[].targetRef.kind=Mesh` and `proxyTypes` where present (incl. system defaults).
- **Info** — ZoneIngress/ZoneEgress if present.
- **Header** — correct CP version; `Includes N CP-managed (policy-role: system) resource(s)`; exit 1.
- **`clean` in isolation** — 0 *operator-authored* blockers and NO `meshServices.mode` warning. The CP-generated system defaults (`mesh-timeout-all-clean`, `mesh-gateways-timeout-all-clean`) use `from`/`to: Mesh`/`proxyTypes`, so `clean` still reports 2 system-marked blockers + warnings and **exit 1** (per the TC-24 decision: system policies are flagged, not skipped — the operator must update them before 3.0). A genuine exit-0/✅ is only reachable on a mesh with no CP-managed defaults.
**Oracle:** Build the expected list explicitly from the fixtures and diff against `actual.md`. FAIL on any **missing** finding (false negative — the dangerous direction), any **extra/wrong-severity** finding (false positive / cry-wolf), any **mis-attributed mesh**, or `clean` being flagged `meshServices.mode is not Exclusive`. Do NOT treat `clean`'s system-default blockers as a failure — those are the decided TC-24 behavior. This is the end-to-end correctness gate the stub cannot fully provide.
**Source:** real-CP run; merge — the user requirement to verify the complete finding-set on a live cluster.

## Risk areas (where bugs most likely hide)

1. **Spec serialization split (TC-23) — highest harm, already bit once.** Core/legacy/Dataplane inline spec; new policies nest under `spec`. A check that reads only `spec` is a silent no-op against half the resources, and a `spec`-wrapping stub will pass it anyway. Any new check MUST be exercised against both encodings (prefer a real CP).
2. **Failure-to-observe rendered as clean (TC-1, TC-6, TC-11, TC-12).** A non-CP, a mid-pagination failure, a 404'd collection, or an unparseable resource must never read as a clean pass — these now drive exit 2/3, not 0. For a gate whose whole job is "did I miss a blocker?", this is the dominant risk class.
3. **Server-controlled exhaustion / non-authoritative limits (TC-5, TC-7, TC-21).** Cursor cycle guard + page cap, `--timeout`-derived client timeout, and the 64 MiB body cap must hold; a hostile/large CP must not hang or OOM the client.
4. **Untrusted input & output side-effects (TC-9, TC-19, TC-20).** `--mesh` path escaping, symlink refusal + atomic write, and the FAILED-stamp on a failed run.

## Out of scope

- Automated/unit tests (belongs to `test-writer`; a smoke test already exists in-repo history).
- Correctness of the *Kuma 3.0 deprecation list itself* beyond what TC-14 spot-checks against `deprecated-features.md`.
- Performance benchmarking beyond the memory/timeout boundary cases above.
- The GUI and any non-CLI surface.

## Resolved decisions (were open questions; now implemented)

- **404 handling:** recorded as a Coverage gap and marked inconclusive (exit 3) — not silently zeroed. (TC-11)
- **Index validation:** the tool asserts `GET /` returns a non-empty `version`; otherwise exit 2. (TC-1)
- **`--mesh` not found:** hard error, exit 2. (TC-8)
- **`--timeout` semantics:** authoritative; `http.Client.Timeout` is derived from it (no hidden 30s cap). (TC-7)
- **System policies:** flagged and marked (operator must update before v3), not skipped. (TC-24)
- **Output atomicity:** write-temp-then-rename, refuse symlinks, FAILED-stamp on failure. (TC-19, TC-20)
- **Inconclusive exit code:** coverage gaps / unparseable resources → exit 3. (TC-26)

## Open questions (still need a decision)

- **`to[].targetRef.kind=Mesh` (warning):** doc-consistent (`deprecated-features.md`) but the most common valid 2.x construct; confirm per-policy-type intent so the warning volume is expected, not noise. (TC-14)
- **`passthrough: false` explicit:** currently flagged like any non-nil value (field removed regardless). Confirm this is desired vs only flagging `true`. (TC-13)

## Persona attribution

- **Bach:** TC-1, TC-3, TC-5, TC-7, TC-9, TC-12, TC-16, TC-19, TC-21
- **Kaner:** TC-4 (shared), TC-6, TC-8 (shared), TC-11, TC-13, TC-14, TC-17, TC-20 (shared), TC-26
- **Hendrickson:** TC-2 (shared), TC-10, TC-15, TC-18, TC-22
- **Real-CP run / merge:** TC-23, TC-24, TC-25 (regressions found against a live CP, not in the persona drafts)
- **Merged/shared:** TC-2, TC-4, TC-6, TC-7, TC-8, TC-16, TC-20
