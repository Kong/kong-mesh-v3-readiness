# Manual Test Results — `kuma3-preflight`

Execution of `docs/test-plan.md`. Driven by a stdlib Python
stub of the CP REST API (scenario-selected handlers) plus a few no-server cases.
Binary: `go build -o /tmp/kuma3-preflight ./cmd/kuma3-preflight` (clean build).

> **Supersedes the prior results in git history.** That run audited an earlier,
> un-hardened build (12 FAIL). The tool source has since been reworked
> (`main.go`/`client.go`/`audit.go`/`report.go`) and this run re-executes the
> full plan against the current binary. Every previously-failing case now passes;
> one cosmetic header nit remains (TC-22).
>
> ⚠️ **READ THE REAL-CP ADDENDUM AT THE BOTTOM FIRST.** The verdict table below
> was produced against a **Python stub** whose fixtures wrapped every resource in a
> `spec` envelope. A real Kuma CP does **not** — core resources (Mesh, Dataplane,
> TrafficPermission, …) inline their spec at the top level. Running the same binary
> against a real k3d CP (2026-06-16) exposed **two HIGH-severity false-negative bugs
> the stub could not surface** (`checkMeshSettings` and `checkDataplanes` are dead),
> plus a cry-wolf on CP-generated system policies. See "Real control-plane execution".

## Verdict summary

| TC | Area | Verdict | One-line finding |
|----|------|---------|------------------|
| TC-1  | Wrong endpoint false-green | ✅ PASS | non-CP 200 → exit 2 FAILED; HTML→decode error, `{}`→"no version" |
| TC-2  | Index 404 / refused / DNS / TLS | ✅ PASS | 4 distinct messages, all exit 2 |
| TC-3  | Token leakage | ✅ PASS | reflected-token 401 body suppressed; `grep SUPERSECRET`=∅ in out+file |
| TC-4  | Empty vs invalid token | ✅ PASS | 401 → exit 2, never clean |
| TC-5  | Non-advancing cursor | ✅ PASS | visited-set catches repeat, aborts in 0.04s exit 2 |
| TC-6  | Failure mid-pagination | ✅ PASS | page-2 401 aborts inside loop, exit 2, no partial report |
| TC-7  | `--timeout` authoritative | ✅ PASS | 5s→abort 5.07s; 35s→abort 35.08s (no hidden 30s cap) |
| TC-8  | `--mesh` absent | ✅ PASS | typo/ghost mesh → exit 2 "not found"; real mesh → scoped exit 1 |
| TC-9  | `--mesh` metacharacters | ✅ PASS | `..`/space/`%` all escaped; no traversal, no path/query corruption |
| TC-10 | Cross-mesh attribution | ✅ PASS | payload-`mesh` attribution; `--mesh` scoping correct |
| TC-11 | 404 vs absent | ✅ PASS | 404 → distinct ⚠️ Coverage-gaps section vs empty ✅ (not byte-identical) |
| TC-12 | Malformed spec | ✅ PASS | unparseable policy surfaced as a warning, not dropped |
| TC-13 | Presence-based detection | ✅ PASS | `passthrough:true`→blocker; omitted & `outbound:{}`→0 (consistent) |
| TC-14 | No cry-wolf | ✅ PASS | every blocker maps to a documented 3.0 change |
| TC-15 | Full legacy + clean | ✅ PASS | 28 blk / 3 warn / 2 info all fire (exit 1); clean → exit 0 |
| TC-16 | Merge + cap boundary | ✅ PASS | 1500 merged, ≤10 examples, `(+1490 more)`; 10→none, 11→`(+1 more)` |
| TC-17 | Legibility | ✅ PASS | true counts "60 found"/"1 found"; lone gateway blocker on own line |
| TC-18 | Determinism | ✅ PASS | 10 runs byte-identical |
| TC-19 | `--output` robustness | ✅ PASS | symlink refused (target intact); perms/missing-dir exit 2; overwrite signaled |
| TC-20 | Output/exit consistency | ✅ PASS | failed run stamps FAILED (no stale ✅); SIGINT all-or-nothing |
| TC-21 | Adversarial bodies | ✅ PASS | huge body bounded ~206 MB via 64 MiB LimitReader; a/b/d/e clear errors |
| TC-22 | Empty estate | ⚠️ PASS* | exit 0, no panic, but header "Meshes scanned: all" misreports 0 meshes |

**21 PASS, 1 PASS-with-caveat, 0 FAIL.**

## Detailed evidence

### ✅ TC-1 — Wrong endpoint
- `GET /` → `200 <html>` → exit 2, FAILED stamp: `decoding ...: invalid character '<'`.
- `GET /` → `200 {}` → exit 2, FAILED stamp: `endpoint ... does not look like a Kuma
  control plane (GET / returned no version)` (`audit.go` asserts `idx.Version != ""`).
No more "Control plane: Kuma / 0 findings / ✅". Non-CP is now a hard operational error.

### ✅ TC-2 — Connectivity
- `GET /`→404: `connecting to control plane: GET /: status 404`
- closed port (`:1`): `... connect: connection refused`
- DNS: `... lookup ...: no such host`
- http→TLS server: `... read: connection reset by peer`
- https→plaintext: `... tls: first record does not look like a TLS handshake`
All exit 2, all distinguishable.

### ✅ TC-3 — Token leakage
`--token SUPERSECRET`, CP 401 body `{"error":"token SUPERSECRET rejected"}`.
stderr: `... GET .../: status 401` — **response body no longer echoed** (`getJSON`
returns `status %d` only). `grep SUPERSECRET` over combined stdout+stderr **and** the
`--output` file → 0 matches. Header-sourced token never appears either.

### ✅ TC-4 — Token semantics
`--token ""` and a wrong token against an auth-required CP → exit 2, `status 401`,
never a clean report. (Message is generic `status 401`, not auth-worded — minor nit.)

### ✅ TC-5 — Cursor loop
Collection `next` resolves to the same RequestURI. `client.list` keeps a `visited`
set: `pagination cursor repeated (/traffic-permissions?size=1000); aborting to avoid
an infinite loop`, exit 2 in **0.04s** (no spin to deadline). Also backstopped by
`maxPages = 100_000`.

### ✅ TC-6 — Mid-pagination failure
`/dataplanes` page-1 (with `next`) → 200, page-2 → 401.
`error: listing dataplanes: GET .../dataplanes?page=2: status 401`, exit 2, **stdout =
FAILED stamp** (no page-1 partial report). Error fires from inside the pagination loop.

### ✅ TC-7 — `--timeout` authoritative
- `GET /` sleeps 20s, `--timeout 5s` → abort at **5.07s**.
- `/meshes` hangs, `--timeout 35s` → abort at **35.08s** (exceeds the old hardcoded
  30s cap — proves it is gone). `newClient` now sets `http.Client{Timeout: timeout}`.
Authoritative in both directions.

### ✅ TC-8 — Absent mesh
`--mesh payment` (typo) and `--mesh ghost` → exit 2, `mesh "X" not found on the control
plane`. Control `--mesh payments` (real) → exit 1, `Meshes scanned: payments`, mTLS
blocker fires. `audit()` errors when `meshFilter != "" && len(meshes)==0`.

### ✅ TC-9 — `--mesh` metacharacters
Scoped paths the server received (via REQLOG):
- `../../meshes/default/dataplanes` → `/meshes/..%252F..%252Fmeshes%252F.../traffic-permissions` — no `/` separators, **no traversal**.
- `a b` → `/meshes/a%2520b/...` — no literal space.
- `default%3f` → `/meshes/default%25253f/...` — `?` stays encoded, no path/query split.
`scopedPath` runs `url.PathEscape` on the untrusted mesh segment. (Special chars get
double-encoded since `url.URL.Path` re-escapes; harmless — real mesh names are RFC-1035.)

### ✅ TC-10 — Cross-mesh attribution
Unscoped `/traffic-permissions` with `mesh` fields default/prod/prod → 3 findings
attributed by payload (`qualified()` uses `it.Mesh`): default/tp-default-1,
prod/tp-prod-1, prod/tp-prod-2. `--mesh prod` → 2 prod items via `/meshes/prod/...`,
default excluded. No mis-attribution / double-count.

### ✅ TC-11 — 404 vs absent (was highest-harm)
"50 TrafficPermissions behind 404" vs "genuinely empty CP" are **not** byte-identical:
the 404 run emits `- Coverage gaps: 1 collection(s)...`, a `⚠️ ... NOT a clean bill of
health` verdict, and a `## Coverage gaps — collections NOT audited` section naming
`/traffic-permissions`. The empty run shows `✅`. `listColl` records `addGap` on 404.
(Both still exit 0 — see Residual observations.)

### ✅ TC-12 — Malformed spec
`meshtrafficpermissions` with `from` as an object → `json.Unmarshal` fails →
`### Unparseable resources / MeshTrafficPermission spec could not be parsed — 1 found`
(`e.g. default/mtp-bad`). Surfaced as a warning, not silently `continue`d.
(Exit 0 since it is a warning — see Residual observations.)

### ✅ TC-13 — Presence-based detection
Same "no passthrough" intent, three serializations:
- `networking.outbound.passthrough: true` → **1 blocker**
- networking omitted → **0 blockers**
- `networking.outbound: {}` → **0 blockers** (was a false positive in the old build)
Detection keys on `spec.Networking.Outbound.Passthrough != nil`, so a defaulted/empty
`outbound` no longer fires. Consistent verdicts for identical intent.

### ✅ TC-14 — No cry-wolf
Each flagged construct cross-checked against `deprecated-features.md`:
removed resources (Resources-dropped / legacy-policies / Gateway tables), the 9 Mesh
settings (Mesh-object-settings table), `from` (L39-49), top-level targetRef≠Mesh/Dataplane
(L71), `to[]`≠Mesh*Service (L72), `proxyTypes` (L73), reachableServices (L20), Dataplane
`networking.gateway` (L105). All documented 3.0 changes; no false positives.
**Note:** `to[].targetRef.kind=Mesh` is flagged (warning) and is the highest-volume
valid 2.x construct — doc-consistent (L72) but still warrants explicit eng confirmation
(open question in the plan).

### ✅ TC-15 — Feature tour
- (a) Fully legacy mesh → **30 blockers** (15 removed resources + 9 Mesh settings +
  `from` + top-level targetRef + reachableServices + gateway-DP + zoneingress/egress),
  **3 warnings** (meshServices.mode, `to[]` kind=Mesh, proxyTypes).
  Exit 1. All severities correct.
- (b) Exclusive + new-policies-only mesh (targetRef.kind=Mesh, to[].kind=MeshService) →
  0 blockers, exit 0, `✅`. No false blocker.

### ✅ TC-16 — Merge + cap
50 meshes × 30 = 1500 → 1 merged row, `1500 found`, 10 examples, `(+1490 more)`.
Exactly 10 → no "+0 more"; exactly 11 → `(+1 more)`.

### ✅ TC-17 — Legibility
60 TrafficRoute + 1 gateway-DP → header `61 blockers`; routes row `60 found` +
`(+50 more)` (true total visible despite cap); gateway blocker `1 found` on its own
line/category.

### ✅ TC-18 — Determinism
10 runs against a frozen multi-mesh dataset (5 meshes × 15, over-cap) → byte-identical
(`renderSection` stable-sorts by category then title; insertion-ordered findings slice).

### ✅ TC-19 — `--output` robustness
- (a) existing non-empty file → atomically overwritten, stderr `report written to ...`
  (signaled, not silent).
- (b) symlink → `refusing to write link.md: destination is a symlink`, exit 2,
  **`secret_target.txt` unchanged** (`writeReport` `Lstat`-checks `ModeSymlink`).
- (c) `/etc/hosts` (no perms) → exit 2, `permission denied`, target intact.
- (d) missing dir → exit 2, `no such file or directory`.

### ✅ TC-20 — Output/exit consistency
- Prior clean `✅` report at `preflight.md`; a run that 500s on the first collection →
  exit 2 and the file is **overwritten with the FAILED stamp** (no stale clean).
- Foreground SIGINT mid-audit (default disposition) → binary killed at 2.00s (exit -2),
  the destination keeps its **prior** content untouched, no half-written report, no
  orphaned `.tmp`. Atomic temp+rename gives all-or-nothing.
  (Harness note: bash `&` sets SIGINT→SIG_IGN, which Go inherits; tested via a Python
  launcher that restores SIG_DFL.)

### ✅ TC-21 — Adversarial bodies
- (a) truncated JSON → `decoding ...: unexpected EOF`, exit 2.
- (b) `text/html` + valid JSON → decoded regardless (1 blocker), exit 1.
- (c) ~150 MB body / 1.2M items → **peak RSS 206 MB**, bounded by
  `io.LimitReader(resp.Body, 64 MiB)`; decoder hits the cap → `unexpected EOF`, exit 2.
  Does not scale with body size (a multi-GB body stays capped).
- (d) `Content-Encoding: gzip` on plaintext → `decoding ...: gzip: invalid header`,
  exit 2, no leak.
- (e) duplicate JSON keys → last wins (`name:"b"`), no crash.
Tradeoff: a genuinely valid collection > 64 MiB also fails (loud `unexpected EOF`, never
a misleading clean) — the safe choice.

### ⚠️ TC-22 — Empty estate
0 meshes, all collections empty → exit 0, no panic, `✅`. But header reads
`Meshes scanned: all` (`report.go`: empty `r.meshes` defaults to `"all"`). For an empty
estate it should read `0` / `none`. Cosmetic; only surviving issue.

## Residual observations (not plan FAILs, worth an eng decision)

1. **Exit code vs coverage gaps (TC-11):** a 404'd collection yields a ⚠️ report but
   still **exit 0**. CI that gates only on `$?` (not the report) would read it as success.
   Consider a distinct exit code (or `2`) when any collection could not be audited.
2. **Exit code vs unparseable (TC-12):** an unparseable resource is a warning → exit 0,
   even though it could hide a blocker. Same gating concern.
3. **Empty-estate header (TC-22):** `Meshes scanned: all` for 0 meshes.
4. **Auth message specificity (TC-4):** generic `status 401`; an auth-specific hint
   would aid operators.
5. **`passthrough: false` explicit (TC-13):** not exercised; current logic flags any
   non-nil `Passthrough` pointer, so an explicit `false` would be flagged a blocker
   (arguably correct — the field is removed regardless of value).
6. **`to[].targetRef.kind=Mesh` (TC-14):** flagged (warning), doc-consistent but the
   most common valid 2.x construct — confirm per-policy-type intent.

## Cross-cutting status

All three risk clusters the plan called out are now closed in this build:
1. **Failure-to-observe rendered as clean** — fixed: non-CP (TC-1), 404 coverage gaps
   (TC-11), parse-skip→warning (TC-12), absent mesh (TC-8).
2. **Server-controlled exhaustion / non-authoritative limits** — fixed: cursor guard +
   page cap (TC-5), `--timeout`-derived client timeout (TC-7), 64 MiB body cap (TC-21c).
3. **Untrusted input & output side-effects** — fixed: `PathEscape` (TC-9), symlink
   refusal + atomic write (TC-19), FAILED-stamp on failed run (TC-20), body suppressed
   in errors (TC-3).

_Harness: `/tmp/k3pf2/server.py`, `/tmp/k3pf2/run.sh`, `/tmp/k3pf2/sigint_test.py`.
Source of truth: `docs/deprecated-features.md`._

---

# Real control-plane execution (addendum, 2026-06-16)

The plan calls for a few cases against a **real** Kuma CP (TC-15 happy path, TC-14
cry-wolf, TC-1/TC-8). Executed against a fresh k3d cluster running this repo's CP
(`kuma-cp 0.0.0-preview.vabc376b0a`, a 2.x build), helm-deployed, port-forwarded on
`:5681`. Binary: `go build -o /tmp/kuma3-preflight ./cmd/kuma3-preflight`.

Fixtures authored on the live CP via `kubectl`:
- 9 legacy resources on `default`: TrafficPermission, TrafficRoute, TrafficLog,
  HealthCheck, CircuitBreaker, Timeout, ProxyTemplate, ExternalService, VirtualOutbound.
- Mesh `legacy` with inline `mtls`, `metrics`, `tracing`, `logging`, `constraints`,
  `routing.{localityAwareLoadBalancing,zoneEgress,defaultForbidMeshExternalServiceAccess}`,
  `networking.outbound.passthrough`.
- Mesh `clean` with `meshServices.mode: Exclusive`.
- New policies on `legacy`: a MeshTrafficPermission using `from`, a MeshHTTPRoute with
  top-level `targetRef.kind: MeshService`.
- A real injected Dataplane carrying `reachableServices`
  (`kuma.io/transparent-proxying-reachable-services` annotation).

## What works against a real CP ✅

- **Removed legacy resources** — all 9 detected (presence-counted, no spec parse).
- **New targetRef policies** — `from`, top-level `targetRef.kind≠Mesh/Dataplane`,
  `to[].kind=Mesh`, `proxyTypes` all fire correctly. New policies carry a real `spec`
  envelope, which is what the tool reads.
- **Connectivity / errors** — `--mesh ghost` → exit 2 + FAILED stamp
  (`mesh "ghost" not found`). Clean build, no panics.
- The CP itself emits `Warning: 'from' field is deprecated…` / `Warning: MeshService
  value for 'targetRef.kind' is deprecated…` on apply — independent corroboration of
  TC-14 (the flagged constructs are genuinely 3.0-deprecated).

## Bugs the stub run could not catch ❌

### BUG-1 [HIGH] `checkMeshSettings` is dead against a real CP — 9 false negatives + 1 false positive

Root cause: the Kuma REST API serializes **core/legacy resources with their spec
fields inlined at the top level**, with **no `spec` key**. New policies nest under
`spec`; Mesh/Dataplane/TrafficPermission/ExternalService/VirtualOutbound do not.

```
GET /meshes/legacy  → {"type":"Mesh","name":"legacy","mtls":{…},"metrics":{…},
                       "tracing":{…},"logging":{…},"routing":{…},"constraints":{…},
                       "networking":{…}}        ← NO "spec" field
GET /meshes/clean   → {"type":"Mesh","name":"clean","meshServices":{"mode":"Exclusive"}}
```

`resourceItem.Spec` (`client.go`) maps `json:"spec"`, so for a Mesh it is always empty.
`checkMeshSettings` (`audit.go:129`) does `json.Unmarshal(m.Spec, &spec)` on nothing →
zero-value `meshSpec` → **none of the 9 Mesh-setting blockers ever fire**:
inline mTLS, passthrough, routing.zoneEgress, defaultForbidMeshExternalServiceAccess,
localityAwareLoadBalancing, metrics, tracing, logging, constraints.

Observed: mesh `legacy` carrying ALL of the above → **0 "Mesh object settings"
blockers**. These are the headline 3.0 migrations (mTLS→MeshIdentity, metrics→MeshMetric,
etc.); the tool silently green-lights every one of them.

Same bug, opposite direction — **false positive**: `meshServices.mode` reads as `""`,
so the Exclusive `clean` mesh is reported `meshServices.mode is not Exclusive
(current: Disabled)`. `--mesh clean` confirms it in isolation. An operator who already
migrated to Exclusive is told to migrate again.

### BUG-2 [HIGH] `checkDataplanes` is dead against a real CP — reachableServices + gateway never fire

Same root cause. `GET /meshes/default/dataplanes` returns
`{"type":"Dataplane","name":…,"networking":{…}}` — `networking` inlined, **no `spec`**.
A real injected Dataplane with
`networking.transparentProxying.reachableServices: [backend_k3pf-test_svc_80]`
(verified present in the API response) produced **0 reachableServices blockers**.
The `networking.gateway` blocker shares the same `it.Spec` path and is dead identically.
Both are BLOCKER-severity 3.0 breaks; both silently pass.

### BUG-3 [MED] Cry-wolf on CP-generated system policies — a clean exit 0 is impossible on any real mesh

Every Kuma mesh auto-creates default policies labelled `kuma.io/policy-role: system`
(`mesh-timeout-all-<mesh>`, `mesh-gateways-timeout-all-<mesh>`,
`mesh-circuit-breaker-all-<mesh>`, `mesh-retry-all-<mesh>`). These use exactly the
constructs the tool flags:
- both default MeshTimeouts use `from` → **BLOCKER** (× number-of-meshes),
- all use `to[].targetRef.kind: Mesh` → warning,
- MeshTimeouts use `targetRef.proxyTypes: [Sidecar|Gateway]` → warning.

Result: a **pristine, untouched `default` mesh reports 2 blockers + 7 warnings, exit 1.**
The operator cannot fix these — they are CP-managed and regenerated by the 3.0 upgrade
itself. `resourceItem` never reads `labels`, so the tool cannot skip `policy-role:
system`. This is the cry-wolf the plan's open question (L211) anticipated, made concrete:
6 of 7 `from` blockers in the all-mesh run are CP system policies, not operator config.

### BUG-4 [LOW] `--address` path component silently ignored

`getJSON` (`client.go`) overwrites `full.Path = path` for every request, discarding
`base.Path`. `--address http://localhost:5681/meshes` and `…/gui` both produced a full,
successful audit (the path was dropped; requests hit the host root). Harmless when the
CP is at `/`, but a CP behind a path-prefixed ingress (`https://gw/kuma`) would be
audited at the wrong paths — and TC-1's "wrong subpath → false green" cannot be tested
this way because the subpath never reaches the server.

## Net

The tool's two spec-parsing check families split cleanly by API serialization:
**new-policy checks work; every core/legacy-resource spec check (all Mesh settings,
all Dataplane settings) is a silent no-op against a real CP.** For a gate whose entire
purpose is "did I miss a 3.0 blocker?", BUG-1 and BUG-2 are exactly the
failure-to-observe-rendered-as-clean class the plan's Risk Area 1 warns about — and the
stub-based pass missed them because its fixtures matched the tool's struct, not the CP.

Fix sketch: when unmarshalling a resourceItem, fall back to the whole object (minus
envelope keys `type/mesh/name/labels/creationTime/modificationTime/kri`) as the spec
when no `spec` key is present; and skip policies labelled `kuma.io/policy-role: system`
(requires capturing `labels` in `resourceItem`).

_Harness/fixtures: `/tmp/k3pf-legacy.yaml`, `/tmp/k3pf-meshes.yaml`, `/tmp/k3pf-newpol.yaml`,
`/tmp/k3pf-workload.yaml`. Cluster: k3d `kuma-1`. Report artifact: `/tmp/k3pf-all.md`._

---

# Real-CP RE-RUN against the hardened build (2026-06-16, BUG-1/2/3/4 fixed)

Re-executed the real-CP plan cases against the **current** binary (`go build -o
/tmp/kuma3-preflight ./cmd/kuma3-preflight`) on the same live k3d CP
(`kuma-cp 0.0.0-preview.vabc376b0a`, port-forward `:5681`). The source has since
landed the fixes the addendum above sketched — `resourceItem.specBytes()` falls back
to the whole raw object when there is no `spec` envelope, `labels` are captured, and
`isSystem()` marks (not skips) `policy-role: system`. `client.prefixed()` honors an
`--address` path prefix. **All four previously-found bugs are now fixed.**

## Verdict (real CP)

| TC / Bug | Was | Now | Evidence |
|---|---|---|---|
| TC-23 / BUG-1 Mesh inline settings | 9 false negatives | ✅ **all 9 fire** | `legacy` → Inline mTLS/metrics/tracing/logging/constraints/passthrough/routing.zoneEgress/defaultForbid…/localityAware all blocked |
| TC-23 / BUG-1 `meshServices.mode` | false positive on `clean` | ✅ **not flagged** | `--mesh clean` emits no "not Exclusive" warning; `default`+`legacy` correctly warned |
| TC-23 / BUG-2 Dataplane reachableServices | dead | ✅ **fires** | `default/reachable-app-…k3pf-test` → reachableServices blocker (real injected DP, spec inlined) |
| TC-24 / BUG-3 system policies | unfixable cry-wolf | ✅ **flagged + marked** | 14 CP-managed marked `(system — CP-managed, update before 3.0)`; header `Includes 14 CP-managed…` |
| TC-24 user policy | n/a | ✅ **flagged UNMARKED** | added `mtp-user-from` in `k3pf-test` (CP role `workload-owner`) → flagged with no system marker |
| TC-25 / BUG-4 path prefix | silently dropped | ✅ **honored** | `--address …/kuma` → requests hit `/kuma/`, CP 404s → exit 2 FAILED (no false green) |

## Root-cause evidence (confirmed live)

```
GET /meshes/legacy        → no "spec" key; mtls/metrics/tracing/logging/routing/networking/constraints inlined at top level
GET /meshes/.../meshtimeouts → has "spec" key (nested envelope)
GET /.../dataplanes        → no "spec" key; networking inlined
```
`specBytes()` returns the nested `spec` for new policies and the whole raw object for
inlined core/Mesh/Dataplane resources — so both encodings are parsed. The split that
killed BUG-1/BUG-2 is now handled.

## Full-audit numbers (all meshes)

27 blockers / 20 warnings / 0 info, exit 1. Includes: 9 removed legacy resources on
`default`, all 9 `legacy` Mesh settings, 6 system MeshTimeout `from` + 1 user MTP `from`
+ 1 user MTP (`workload-owner`), 1 bad-targetRef MeshHTTPRoute, 1 Dataplane
reachableServices. Warnings: `meshServices.mode` for `default`+`legacy` (NOT `clean`),
`to[].kind=Mesh` and `proxyTypes` on system defaults.

## Exit-code matrix (TC-26, live)

`clean Exclusive but with system defaults` → **1** · blocker mesh → 1 · refused/DNS/prefix-404/ghost-mesh → **2** · (3 = coverage-gap/unparseable, exercised via stub above).

## ⚠️ Doc inconsistency found (not a tool bug)

TC-27 and B-4 expect "`clean` in isolation → 0 blockers, exit 0, ✅". This is now
**unachievable on any real CP**: the CP auto-creates `mesh-timeout-all-clean` /
`mesh-gateways-timeout-all-clean` defaults that use `from`, and the TC-24 decision
(flag + mark system policies, do NOT skip) makes those blockers. So `--mesh clean`
correctly returns **2 blockers, exit 1** — both system-marked. The TC-27/B-4 "exit 0"
expectation predates the TC-24 decision and should be amended to "0 *operator-authored*
blockers; only system-marked CP defaults remain (exit 1)". A genuinely 0-blocker mesh
requires either no CP-managed defaults or the operator first updating them.

_Binary: current HEAD. Cluster: k3d `kuma-1` (pre-existing, fixtures intact). Added
fixture: `mtp-user-from` in `k3pf-test`. Reports: `/tmp/k3pf-all.md`, `/tmp/b9.md`._
