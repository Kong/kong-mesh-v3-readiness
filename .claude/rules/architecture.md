# Architecture invariants — do not break

- **One model, three renderers.** Everything renders from `reportModel` (`model.go`);
  markdown, JSON, and HTML must never disagree. `--from-json` reloads `reportModel` and
  re-renders, so the JSON shape is a stable contract. Bump `reportSchema` (`model.go:13`)
  on incompatible changes.
- **Exit codes gate CI** (set in `main.run`): `0` clean · `1` blockers · `2` operational
  error · `3` inconclusive. Keep `exitForStatus`, `report.status()`, and these in sync.
- **Never emit a misleading clean report.** A 404 on a collection is a *coverage gap*
  (`addGap`); an unparseable spec is a *parse error* (`parseErrors++`) — both make the run
  `inconclusive` (exit 3), not clean. A non-Kuma endpoint, an empty `--mesh` match, or a 404
  on `/meshes` is a hard error (exit 2). Don't treat "not observed" as "absent".
- **Failures stamp the output.** On audit error the destination is overwritten with a FAILED
  report (`failureContent`) so a stale clean file is never mistaken for current.
- **HTML is fully self-contained** — inline CSS/JS, zero network requests, works from
  `file://`. Never add an external URL or CDN reference (a test enforces this). Report JSON
  is embedded via `json.Marshal` (escapes `<>&`) so it can't break out of `<script>`.
- **Security in `client.go`:** never echo response bodies into errors (may reflect the
  bearer token); cap bodies at `maxBodyBytes`; backstop pagination (`maxPages` +
  visited-cursor loop guard); percent-escape the untrusted `--mesh` value in paths.
- **File writes are atomic** (`writeReport`: temp file + rename) and refuse to follow a
  symlink at the destination. Keep both properties.
- **Deterministic output:** findings/coverage are sorted in `toModel` (`model.go:101`)
  before rendering. No map-iteration order or timestamps in the rendered body (`generatedAt`
  aside).

## Output data model

- Finding type: `finding` struct (`report.go:11`) — `{ severity, category, title, detail,
  count, examples[] }`. `add()` (`report.go:50`) merges duplicates, appends example refs up
  to `exampleCap` (10). Rendered as one bullet per `(severity, category, title)` with merged
  count + capped example list.
- `findingModel` (`model.go:58`) is the serialized form; JSON top-level contract is
  `reportModel` (`model.go`): `schema`, `tool`, `status`, `controlPlane`, `summary`,
  `findings[]`, `coverageGaps[]`, `manualChecks[]`.

## Extensibility

To add an audit dimension: add a `check*` method in `audit.go` called from `audit()` (or
extend one), surface any new field in `reportModel` only if the JSON contract needs it,
render it in all three formats (`model.go` / `html.go`), and add a test in `render_test.go`.

## Anti-patterns

- Decoding a whole CP resource into a giant struct — unmarshal only the fields a check
  inspects. Unknown fields are ignored on purpose so the tool survives CP version skew.
- Treating a 404 / parse failure as "no findings" — that fakes a clean pass.
- Adding rendering logic that reads the live `report` instead of `reportModel` — the three
  formats would drift and `--from-json` would lose it.
- Putting a deprecation rule only in `docs/deprecated-features.md` or a comment without a
  check in `audit.go` — docs are reference, `audit.go` is behavior.
- Logging or error-wrapping a raw HTTP response body — it can contain the bearer token.
- Non-deterministic output (map ranges, unsorted slices) in the rendered report.
