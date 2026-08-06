# Architecture invariants — do not break

- **One model, N renderers.** Everything renders from a single model — the CP audit from
  `preflight.Report` (`preflight/model.go`) into JSON (`RenderJSON`) + HTML (`RenderHTML`);
  `--classify` from `classificationModel` (`cmd/kuma3-preflight/classify_model.go`) into
  Markdown + JSON + HTML. Within each, the formats must never disagree (Markdown is
  classify-only — a CP audit emits JSON or HTML, default HTML). `preflight.ParseReport`
  reloads a `Report` and re-renders (the CLI's `--from-json` uses it), so the JSON shape is a
  stable contract. Bump `preflight.SchemaVersion` (`preflight/model.go`) on incompatible
  changes.
- **Exit codes gate CI** (derived in `cmd/kuma3-preflight/main.go`'s `run`/`exitForStatus`):
  `0` clean · `1` blockers · `2` operational error · `3` inconclusive. Keep `exitForStatus`,
  the internal `collector.status()` (`preflight/model.go`), and `preflight.Status*` constants
  in sync.
- **Never emit a misleading clean report.** A 404 on a collection is a *coverage gap*
  (`addGap`); an unparseable spec is a *parse error* (`parseErrors++`) — both make the run
  `inconclusive` (exit 3), not clean. A non-Kuma endpoint, an empty `--mesh` match, or a 404
  on `/meshes` is a hard error (`preflight.Audit` returns an error; the CLI exits 2). Don't
  treat "not observed" as "absent".
- **Failures stamp the output.** On audit error the destination is overwritten with a FAILED
  report (`preflight.FailureReport`) so a stale clean file is never mistaken for current.
- **HTML is fully self-contained** — inline CSS/JS, zero network requests, works from
  `file://`. Never add an external URL or CDN reference (a test enforces this). Report JSON
  is embedded via `json.Marshal` (escapes `<>&`) so it can't break out of `<script>`.
- **Security in `preflight/client.go`:** never echo response bodies into errors (may reflect
  the bearer token); cap bodies at `maxBodyBytes`; backstop pagination (`maxPages` +
  visited-cursor loop guard); percent-escape the untrusted mesh-filter value in paths.
- **File writes are atomic** (`cmd/kuma3-preflight/main.go`'s `writeReport`: temp file +
  rename) and refuse to follow a symlink at the destination. Keep both properties.
- **Deterministic output:** findings/coverage are sorted in `toModel`
  (`preflight/model.go`) before rendering. No map-iteration order or timestamps in the
  rendered body (`generatedAt` aside).
- **The `preflight` package makes no network calls beyond the audited control plane** and
  never prints, logs, or calls `os.Exit` — it is imported by other Go programs, not just the
  CLI. The GitHub latest-patch lookup (`fetchLatestPatch` et al.) is a CLI-only concern in
  `cmd/kuma3-preflight/release.go`; `preflight.Audit` takes the already-resolved patch via
  `Options.LatestPatch` and degrades gracefully (a coverage gap) when it's empty.

## Output data model

- Internal finding type: `rawFinding` struct (`preflight/report.go`) — `{ severity, category,
  title, detail, count, examples[] }`, accumulated on the internal `collector` type (also
  `report.go`). `add()`/`addDoc()` merge duplicates, appends example refs up to
  `preflight.ExampleCap` (10). Rendered as one bullet per `(severity, category, title)` with
  merged count + capped example list.
- `preflight.Finding` (`preflight/model.go`) is the serialized form; JSON top-level contract
  is `preflight.Report` (`preflight/model.go`): `schema`, `tool`, `status`, `controlPlane`,
  `summary`, `findings[]`, `coverageGaps[]`, `manualChecks[]`.

## Extensibility

To add an audit dimension: add a `check*` method in `preflight/audit.go` called from
`audit()` (or extend one), surface any new field in `preflight.Report` only if the JSON
contract needs it, render it in all three formats (`preflight/model.go` / `preflight/html.go`),
and add a test in `preflight/render_test.go`.

## Anti-patterns

- Decoding a whole CP resource into a giant struct — unmarshal only the fields a check
  inspects. Unknown fields are ignored on purpose so the tool survives CP version skew.
- Treating a 404 / parse failure as "no findings" — that fakes a clean pass.
- Adding rendering logic that reads the live `collector` instead of `preflight.Report` — the
  three formats would drift and `ParseReport` would lose it.
- Putting a deprecation rule only in `docs/deprecated-features.md` or a comment without a
  check in `preflight/audit.go` — docs are reference, `audit.go` is behavior.
- Logging or error-wrapping a raw HTTP response body — it can contain the bearer token.
- Non-deterministic output (map ranges, unsorted slices) in the rendered report.
- Adding a network call (or a `flag.*`/`os.Exit`/`fmt.Print*`) inside `preflight/` — that's a
  CLI-only concern and belongs in `cmd/kuma3-preflight/`.
