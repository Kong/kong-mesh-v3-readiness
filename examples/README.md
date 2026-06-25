# Example reports

Self-contained `kuma3-preflight` HTML reports (`--format html`, the default) — open any in a
browser to see exactly what an operator sees before upgrading to Kuma 3.0. Each is rendered
from a static fixture in [`json/`](json/), chosen to cover every report state and a realistic
range of estate sizes (a spotless, fully-migrated estate → 7,490 blockers across 20 meshes).
Nothing is fetched at view time, so they work straight from a `file://` URL.

| File | CP | Mode | Meshes | State |
|---|---|---|---|---|
| [`html/multizone-all-clear.html`](html/multizone-all-clear.html) | Kong Mesh | global | 6 | spotless — migration done, upgrade-ready |
| [`html/kubernetes-clean.html`](html/kubernetes-clean.html) | Kuma | zone | 1 | clean, with advisories |
| [`html/universal-standalone.html`](html/universal-standalone.html) | Kuma | standalone | 1 | 53 blockers |
| [`html/kubernetes-all-meshes.html`](html/kubernetes-all-meshes.html) | Kong Mesh | zone | 3 | 41 blockers |
| [`html/kubernetes-zone-medium.html`](html/kubernetes-zone-medium.html) | Kuma | zone | 5 | 280 blockers (~320 DPPs) |
| [`html/multizone-global-large.html`](html/multizone-global-large.html) | Kong Mesh | global | 12 | 1,577 blockers (~1,680 DPPs) |
| [`html/universal-global-xlarge.html`](html/universal-global-xlarge.html) | Kuma | global | 20 | 7,490 blockers (~5,200 DPPs) |
| [`html/inconclusive-coverage-gaps.html`](html/inconclusive-coverage-gaps.html) | Kuma | zone | 3 | inconclusive (coverage gaps) |
| [`html/audit-failed.html`](html/audit-failed.html) | — | — | — | failed (endpoint is not a CP) |

## Regenerating

The JSON fixtures in `json/` are the source of truth; the HTML is rendered from them, so the
checked-in pages can never drift from the template (`cmd/kuma3-preflight/html.go`). After
changing the template or a fixture:

```bash
mise run examples              # build the CLI + render every fixture
# or directly:
examples/regen.sh              # same (builds the binary first)
examples/regen.sh --no-build   # reuse an existing bin/kuma3-preflight
```

To add an example, drop a `reportModel` JSON into `json/` and re-run — it renders to
`html/<name>.html` automatically. (You can also capture a live control plane straight to a
file: `kuma3-preflight --address http://localhost:5681 --output examples/html/<name>.html`.)

## Kubernetes vs Universal — CP-managed defaults

Both CPs inline core/Mesh/Dataplane spec the same way, so every spec-level check fires
identically. The difference is in **CP-managed default policies**:

- **Kubernetes** labels its auto-generated defaults (`mesh-timeout-all-<mesh>`, …) with
  `kuma.io/policy-role: system`. The report tags each such resource and counts them under
  **System-managed** in the summary.
- **Universal** does **not** set that label. The same defaults are still flagged as blockers,
  but without the marker and without the count.

This is CP behavior, not a tool difference — the tool reflects the label the CP provides.
The `Dataplane has a probes section` check is also Universal-only (on Kubernetes, probes are
pod-derived and intentionally skipped).
