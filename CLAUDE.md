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
  - `model.go` `reportModel` + renderers · `html.go` embedded HTML
  - `render_test.go` unit/render tests · `golden_test.go` mock-CP golden tests
    (fixtures + reference JSON under `testdata/golden/<scenario>/`)
- `docs/` — `deprecated-features.md` (3.0 deprecations the checks track), `test-plan.md`,
  `test-setup.md` (k3d + Universal CP), `test-results.md`
- `examples/` real captured reports · `bin/` build output (gitignored) · `mise.toml` tool pins

## Commands

```bash
go build -o bin/kuma3-preflight ./cmd/kuma3-preflight       # build
go run ./cmd/kuma3-preflight --address http://localhost:5681 --output report.html  # audit a CP
go test ./...                                               # all tests
go test ./... -run TestRenderClassificationFormats -v      # one test
go test ./... -run TestGoldenReports -update                # refresh golden JSON refs
```

JSON-in-CI then HTML offline: `--format json --output report.json`, then
`--from-json report.json --format html --output report.html`. Against a k8s zone CP,
port-forward first: `kubectl -n kuma-system port-forward svc/kuma-control-plane 5681:5681`
(see `docs/test-setup.md`).

## Pre-commit quality gates

Run via `mise` (pins the toolchain). All must pass before a change is done:

```bash
go test ./...        # all tests pass
golangci-lint run    # 0 issues (pinned 2.12.2; no .golangci.yml, runs with defaults)
go vet ./...         # clean
gofmt -l cmd/        # prints nothing (no unformatted files)
```

Fix root causes — never suppress a linter finding with an ignore/skip directive.

## Tech stack

- Go (`go.mod` declares `go 1.23`; toolchain pinned to **1.26.4** via `mise.toml`).
- Module `github.com/Kong/kong-mesh-v3-readiness`; build uses `GOFLAGS=-mod=mod` (`mise.toml`).
- Tests: stdlib `testing` only — table-driven + substring assertions, plus
  file-based golden tests (`golden_test.go`) that audit a mock CP (`httptest`)
  and diff the rendered JSON against `testdata/golden/<scenario>/report.golden.json`
  (regenerate with `-update`).
- **Dependencies: none** (stdlib-only; README advertises this). Adding a third-party dep is
  allowed when it clearly earns its place — then update the README's stdlib-only claim, run
  `go mod tidy`, prefer the smallest option.

## Working on the CLI

- **Adding / changing a deprecation check** (where each check shape lives, severity choices):
  see [.claude/rules/adding-checks.md](.claude/rules/adding-checks.md).
- **Architecture invariants, data model, anti-patterns** (one-model-three-renderers, exit
  codes, security, atomic writes): see [.claude/rules/architecture.md](.claude/rules/architecture.md).
