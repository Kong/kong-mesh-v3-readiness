# Classifying Kuma e2e tests by Kuma-3.0 deprecated-feature usage

Goal: point `kuma3-preflight`'s deprecation catalog at the **Kuma e2e suite** to see which
tests exercise features removed/deprecated in Kuma 3.0, so they can be **removed/replaced**
(the test's subject is a removed resource) or **rewritten** (a removed thing is only
scaffolding for an unrelated test).

Two complementary signals, combined by `--classify`:

- **Static** — scan the e2e Go/YAML sources. Fast, deterministic, per-feature attribution,
  no e2e run. Catches inline YAML and the known framework helpers/builders.
- **Dynamic** — run `kuma3-preflight` against the live shared CP after each spec during an
  e2e run, tagged by spec name. Catches resources built programmatically that a source grep
  misses. Requires the opt-in capture hook (below) and an actual e2e run.

## 1. Static only (no e2e run)

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight
./bin/kuma3-preflight --classify \
  --source-dir ~/kong/kuma/test/e2e_env/universal \
  --format markdown --output classification.md
```

Point `--source-dir` at a single e2e env dir (e.g. `test/e2e_env/universal`,
`test/e2e_env/kubernetes`, or a `test/e2e/<suite>`); each immediate subdirectory is treated
as one "feature" (one test). This alone answers most of the question.

## 2. Dynamic capture during an e2e run

The capture hook lives in the **Kuma** repo (it needs the live CP address mid-run). It is
**opt-in and a no-op** unless two env vars are set, so it is safe to keep in the suite:

- `test/framework/preflight.go` — `CapturePreflight(specName, addr)` /
  `PreflightCaptureEnabled()`.
- `test/e2e_env/universal/universal_suite_test.go` — a top-level `AfterEach` that, when
  enabled, snapshots `universal.Cluster.GetKuma().GetAPIServerAddress()` after every spec.

Run the universal suite (it already runs `--procs 1`, so snapshots are serial/clean):

```bash
# 1. Build the tool in this repo
go build -o "$PWD/bin/kuma3-preflight" ./cmd/kuma3-preflight

# 2. Run the Kuma universal e2e suite with capture enabled
cd ~/kong/kuma
KUMA3_PREFLIGHT_BIN="/abs/path/to/v3-readiness/bin/kuma3-preflight" \
KUMA3_PREFLIGHT_DIR="$PWD/preflight-out" \
  make test/e2e-universal
# (smoke a subset with e.g. GINKGO_E2E_TEST_FLAGS="--focus=TrafficRoute")
```

Each spec writes `preflight-out/<NNNN>-<spec-slug>.json` (sequence-numbered so lexical order
matches execution order). Capture never fails a test: exit 1 (blockers) / 3 (inconclusive)
are expected and the snapshot is still written.

## 3. Merge static + dynamic into one report

```bash
./bin/kuma3-preflight --classify \
  --source-dir ~/kong/kuma/test/e2e_env/universal \
  --reports-dir ~/kong/kuma/preflight-out \
  --format html --output classification.html
```

## How features are classified

- **REMOVE/REPLACE** — the feature's name matches a **removed** resource kind it uses (e.g.
  `trafficroute/` uses `TrafficRoute`). The test exists to exercise a resource gone in 3.0;
  port it to the `Mesh*` equivalent (which other dirs usually already test) or delete it.
- **REWRITE** — uses a deprecated feature only as scaffolding (e.g. inline `mtls:` on a Mesh,
  or a legacy policy in a test about something else). Migrate the scaffolding (e.g. inline
  mTLS → MeshIdentity + MeshTrust) without dropping the test's real subject.

The deprecation catalog is shared with the live auditor (`legacyMeshScoped` in
`cmd/kuma3-preflight/audit.go`); a unit test (`TestMarkerCatalogInSync`) fails if a removed
kind ever lacks a source marker.

## Attribution caveats

- The shared-CP snapshot is **cumulative**: a deprecation is attributed to the **first**
  spec that introduces it (consecutive delta). Resources a spec creates and deletes within
  its own per-test cleanup are gone by the (outer) snapshot time — those are covered by the
  static pass instead. Net effect ≈ per-feature attribution; static gives precise file:line.
- Static markers are intentionally simple regexes (inline `type:` + known helper/builder
  names). Field-level deprecations inside new policies are best caught dynamically.

## Extending beyond universal

Wire the same one-line `AfterEach` into `test/e2e_env/kubernetes` /
`test/e2e_env/multizone` suites. For multizone, capture against the **global** CP — one
audit covers the whole estate (resources/policies are KDS-synced; per-zone config comes from
`GET /zones+insights`).
