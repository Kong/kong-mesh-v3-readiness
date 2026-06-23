# Nightly e2e v3-readiness CI pipeline

Automates what we did by hand: run the e2e suites, capture a `kuma3-preflight` audit
after every spec, and classify the results into a "what still uses Kuma-3.0-removed
features" report the team can track over time.

## Shape

- **Tool published from this repo (GoReleaser).** `.goreleaser.yaml` + `.github/workflows/
  release.yml`: a `v*` tag builds the cross-platform `kuma3-preflight` binary and attaches
  `kuma3-preflight_<os>_<arch>.tar.gz` + `checksums.txt` to a GitHub Release. The CI workflows
  **download** that binary — they never vendor or rebuild the source.
- **Reusable workflow in kuma** — `.github/workflows/e2e-v3-readiness.yml`
  (`on: workflow_call` + nightly `schedule`). Jobs:
  1. `audit` (matrix over `universal`/`kubernetes`/`multizone`) — downloads the released
     `kuma3-preflight` binary (checksum-verified), then reuses the repo's own `run-e2e`
     action to build images and run `make test/e2e-<env>` with `KUMA3_PREFLIGHT_BIN` +
     `KUMA3_PREFLIGHT_DIR` set, so the capture hook fires per spec; uploads the snapshot JSONs.
  2. `report` — downloads all snapshot artifacts, runs `--classify` per env, writes the
     markdown into the job summary, uploads md/json/html as `v3-readiness-report`, and
     **fails if no env captured anything** (so a broken nightly goes red, not silently green).
- **kong-mesh caller** — `.github/workflows/e2e-v3-readiness.yaml` just
  `uses: kumahq/kuma/.github/workflows/e2e-v3-readiness.yml@<sha>`. Works because kong-mesh
  `include`s kuma's `mk/e2e.new.mk` (same `make test/e2e-<env>` targets); the reusable
  workflow checks out the caller for the e2e run and downloads the same released binary.

## The capture hook

`test/framework/preflight.go` adds `CapturePreflightCluster(specName, cluster)`, wired as a
top-level `AfterEach` in each of the three suite bootstraps. No-op unless both env vars are
set. Snapshot filenames carry the Ginkgo parallel-process index (no cross-process collisions)
and each capture runs under a hard context timeout. Multizone captures the **global** CP (one
audit covers every zone via `/zones+insights`).

## Prerequisites / decisions

- **Tool home + access.** Source of truth is this repo (`cmd/kuma3-preflight`); CI consumes
  the GoReleaser **release binary**. For public kuma CI to fetch it, the release assets must
  be reachable — i.e. make this repo public (or split out just the tool), or provide a token
  to the download step.
- **Cut a release.** Tag `v0.1.0` (after committing the tool) → `release.yml` publishes the
  binary the nightly downloads. Pin `tool_version` to that tag for reproducibility (default
  `latest`).
- **kong-mesh secrets/vars.** `KMESH_LICENSE_JSON` secret; e2e runner via `vars.RUNS_ON_*`.
- **Cross-org reuse.** Kong org must allow reusable workflows from `kumahq/*`.
- **Runner size.** e2e is heavy (multizone = 5 clusters) — point `runner` at a large runner.
- **Catalog gap.** The deprecation catalog is kuma-OSS; Kong-Mesh enterprise removals need
  catalog additions to be caught.

## Reading the report

Each env's classification buckets findings into **A** (test-authored deprecated usage — the
signal), **B** (CP/framework default-policy noise), **C** (CP config). Track bucket-A counts
over time as the burn-down. Future: post a progress delta to umbrella kumahq/kuma#17001 and/or
publish the HTML to Pages.
