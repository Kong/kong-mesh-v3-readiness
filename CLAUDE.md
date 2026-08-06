# v3-readiness

Tooling + manual-test material auditing a running **Kuma 2.x** control plane (CP) for
**Kuma 3.0** upgrade readiness. Shipped artifact: `kuma3-preflight` — a Go CLI that audits a
CP over its REST API and emits a blockers/manual report as JSON or self-contained HTML
(default HTML; Markdown is produced only by its `--classify` mode). Single-purpose repo —
keep it focused on the preflight CLI + its docs.

## Layout

- `cmd/kuma3-preflight/` — the entire CLI (one `package main`):
  - `main.go` flags / `--from-json` / exit codes / atomic write · `client.go` HTTP client
  - `audit.go` **all audit logic + deprecation check definitions** · `report.go` finding types
  - `model.go` renderers for `reportModel` (alias for `reportmodel.Report`) · `html.go` embedded HTML
  - `render_test.go` unit/render tests · `golden_test.go` mock-CP golden tests
    (fixtures + reference JSON under `testdata/golden/<scenario>/`)
- `reportmodel/` — the JSON contract types (`Report`, `Classification` + nested types) as an
  importable package, so they can be reflected from outside `package main`. `cmd/kuma3-preflight`
  aliases every type back to its old unexported name (`type reportModel = reportmodel.Report`,
  etc.) so all existing call sites are unchanged — this package owns only the struct shapes, not
  the audit/render logic.
- `tools/openapigen/` — a separate Go module (own `go.mod`, `replace`d back to the main module)
  that reflects `reportmodel` types into `docs/openapi.yaml` via `invopop/jsonschema` +
  `sigs.k8s.io/yaml`. Isolated so its dependencies never touch the main module's `go.mod` (kept
  stdlib-only). Regenerate with `go generate ./...` from the repo root after changing a
  `reportmodel` type; doc comments on `reportmodel` types/fields become JSON Schema
  `description`s, `jsonschema:"..."` struct tags drive enums/formats/limits.
- `docs/` — `deprecated-features.md` (3.0 deprecations the checks track), `test-plan.md`,
  `test-setup.md` (k3d + Universal CP), `test-results.md`, `openapi.yaml` (generated, see above)
- `examples/` real captured reports · `bin/` build output (gitignored) · `mise.toml` tool pins

## Commands

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight       # build
go run ./cmd/kuma3-preflight --address http://localhost:5681 --output report.html  # audit a CP
go test ./...                                               # all tests
go test ./... -run TestRenderClassificationFormats -v      # one test
go test ./... -run TestGoldenReports -update                # refresh golden JSON refs
go generate ./...                                           # regenerate docs/openapi.yaml
```

JSON-in-CI then HTML offline: `--format json --output report.json`, then
`--from-json report.json --format html --output report.html`. Against a k8s zone CP,
port-forward first: `kubectl -n kuma-system port-forward svc/kuma-control-plane 5681:5681`
(see `docs/test-setup.md`).

## Pre-commit quality gates

Run via `mise` (pins the toolchain). All must pass before a change is done:

```bash
go test ./...              # all tests pass
golangci-lint run          # 0 issues (pinned 2.12.2; config .golangci.yml, modeled on Kuma's)
nilaway ./...               # 0 nil-panic findings (Uber NilAway, pinned via mise.toml)
go vet ./...               # clean
gofmt -l cmd/ reportmodel/ # prints nothing (no unformatted files; .golangci.yml also enforces gofumpt+gci)
```

These all run against the main module (`cmd/kuma3-preflight` + `reportmodel`) via the module's
`go.mod`. `tools/openapigen` is a separate module (its own `go.mod`) and isn't covered by any of
the above — it has no dependency-graph impact on the shipped binary, so check it independently
(`cd tools/openapigen && go build ./... && go vet ./...`) after touching it.

`mise run check` runs them all. Fix root causes — never suppress a linter finding with an
ignore/skip directive. NilAway false positives (its known limits: the `net/http` `err`/`resp`
contract, map-key→value provenance, slicing a possibly-nil slice) are resolved with an
explicit nil-guard or a small restructure, never a suppression.

## Tech stack

- Go (`go.mod` declares `go 1.23`; toolchain pinned to **1.26.4** via `mise.toml`).
- Module `github.com/Kong/kong-mesh-v3-readiness`; build uses `GOFLAGS=-mod=mod` (`mise.toml`).
- Tests: stdlib `testing` only — table-driven + substring assertions, plus
  file-based golden tests (`golden_test.go`) that audit a mock CP (`httptest`)
  and diff the rendered JSON against `testdata/golden/<scenario>/report.golden.json`
  (regenerate with `-update`).
- **Dependencies: none** for the main module — `cmd/kuma3-preflight` + `reportmodel` (stdlib-only;
  README advertises this). Adding a third-party dep to the main module is allowed when it clearly
  earns its place — then update the README's stdlib-only claim, run `go mod tidy`, prefer the
  smallest option. `tools/openapigen` is the one exception: its own `go.mod` carries
  `invopop/jsonschema` + `sigs.k8s.io/yaml`, isolated from the main module by design.

## Working on the CLI

- **Adding / changing a deprecation check** (where each check shape lives, severity choices):
  see [.claude/rules/adding-checks.md](.claude/rules/adding-checks.md).
- **Architecture invariants, data model, anti-patterns** (one-model-three-renderers, exit
  codes, security, atomic writes): see [.claude/rules/architecture.md](.claude/rules/architecture.md).
