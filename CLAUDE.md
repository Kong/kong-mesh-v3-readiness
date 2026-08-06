# v3-readiness

Tooling + manual-test material auditing a running **Kuma 2.x** control plane (CP) for
**Kuma 3.0** upgrade readiness. Shipped artifact: `kuma3-preflight` — a Go CLI that audits a
CP over its REST API and emits a blockers/manual report as JSON or self-contained HTML
(default HTML; Markdown is produced only by its `--classify` mode). Single-purpose repo —
keep it focused on the preflight CLI + its docs.

## Layout

- `preflight/` — the importable audit engine (`package preflight`,
  `github.com/Kong/kong-mesh-v3-readiness/preflight`):
  - `preflight.go` public entrypoint (`Audit`, `Options`, `Report`, `RemovedKinds`)
  - `client.go` HTTP client · `audit.go` **all audit logic + deprecation check definitions**
  - `report.go` internal finding accumulator · `model.go` `Report` model + JSON/HTML renderers
  - `html.go` embedded HTML · `semver.go` version parsing/comparison
  - `render_test.go`/`golden_test.go`/etc. white-box tests (package `preflight`);
    `api_test.go` black-box tests of the public surface (package `preflight_test`)
  - `testdata/golden/<scenario>/` golden fixtures + reference JSON
- `cmd/kuma3-preflight/` — the CLI (`package main`), a thin wrapper around `preflight`:
  - `main.go` flags / `--from-json` / exit codes / atomic write
  - `release.go` GitHub latest-patch lookup (CLI-only network call; never in `preflight`)
  - `classify.go`/`classify_model.go` the `--classify` e2e-test scanner (its own Markdown model)
- `reportmodel/` — the `--classify` JSON contract (`Classification` + nested types), plus
  **compatibility aliases** for the CP-audit types (`type Report = preflight.Report`, etc.)
  so code written against the older import path keeps compiling. `preflight` owns those
  structs — it defines `RenderJSON`/`RenderHTML` on `Report` — so new code imports
  `preflight` directly. This package holds struct shapes only, never audit/render logic.
- `tools/openapigen/` — a separate Go module (own `go.mod`, `replace`d back to the main module)
  that reflects `preflight.Report` and `reportmodel.Classification` into `docs/openapi.yaml`
  via `invopop/jsonschema` + `sigs.k8s.io/yaml`. Isolated so its dependencies never touch the
  main module's `go.mod` (kept stdlib-only). Regenerate with `go generate ./...` from the repo
  root after changing either contract type; doc comments on those types/fields become JSON
  Schema `description`s, `jsonschema:"..."` struct tags drive enums/formats/limits.
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
go test ./...        # all tests pass
golangci-lint run    # 0 issues (pinned 2.12.2; config .golangci.yml, modeled on Kuma's)
nilaway ./...         # 0 nil-panic findings (Uber NilAway, pinned via mise.toml)
go vet ./...         # clean
gofmt -l .           # prints nothing (no unformatted files; .golangci.yml also enforces gofumpt+gci)
```

These all run against the main module (`preflight` + `cmd/kuma3-preflight` + `reportmodel`) via
the module's `go.mod`. `tools/openapigen` is a separate module (its own `go.mod`) and isn't
covered by any of the above — it has no dependency-graph impact on the shipped binary, so check
it independently (`cd tools/openapigen && go build ./... && go vet ./...`) after touching it.

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
- **Dependencies: none** for the main module — `preflight` + `cmd/kuma3-preflight` +
  `reportmodel` (stdlib-only;
  README advertises this). Adding a third-party dep to the main module is allowed when it clearly
  earns its place — then update the README's stdlib-only claim, run `go mod tidy`, prefer the
  smallest option. `tools/openapigen` is the one exception: its own `go.mod` carries
  `invopop/jsonschema` + `sigs.k8s.io/yaml`, isolated from the main module by design.

## Working on the CLI

- **Adding / changing a deprecation check** (where each check shape lives, severity choices):
  see [.claude/rules/adding-checks.md](.claude/rules/adding-checks.md).
- **Architecture invariants, data model, anti-patterns** (one-model-three-renderers, exit
  codes, security, atomic writes): see [.claude/rules/architecture.md](.claude/rules/architecture.md).
