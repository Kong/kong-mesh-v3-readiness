#!/usr/bin/env bash
#
# Regenerate every examples/html/<name>.html from its committed
# examples/json/<name>.json fixture.
#
# The JSON fixtures are the source of truth; this script only re-renders them
# through the embedded HTML template (cmd/kuma3-preflight/html.go), so the
# checked-in HTML can never drift from the template. Run it after changing the
# template or a fixture.
#
# Usage:
#   examples/regen.sh            # rebuild the binary, render every fixture
#   examples/regen.sh --no-build # skip the build, reuse bin/kuma3-preflight
#
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root
JSON_DIR="examples/json"
HTML_DIR="examples/html"
BIN="bin/kuma3-preflight"

# Honour the pinned toolchain (GOFLAGS, Go version) when mise is available.
run() { if command -v mise >/dev/null 2>&1; then mise exec -- "$@"; else "$@"; fi; }

if [[ "${1:-}" != "--no-build" ]]; then
  echo "building $BIN ..."
  run go build -o "$BIN" ./cmd/kuma3-preflight
fi
[[ -x "$BIN" ]] || { echo "error: $BIN not found - run without --no-build" >&2; exit 1; }

mkdir -p "$HTML_DIR"
shopt -s nullglob
count=0
for json in "$JSON_DIR"/*.json; do
  name="$(basename "$json" .json)"
  out="$HTML_DIR/$name.html"
  rm -f "$out"
  # The CLI's exit code encodes the report status, not a render failure:
  # 0 clean, 1 blockers, 2 operational/failed, 3 inconclusive. A successful
  # render of any of those still writes the HTML, so success == file written
  # (with a status code <= 3); anything higher is a real CLI error.
  # Capture the CLI's output and only surface it on failure, so a normal run
  # stays quiet but a broken fixture still shows the CLI's own diagnostics.
  set +e
  render_output="$("$BIN" --from-json "$json" --format html --output "$out" 2>&1)"
  rc=$?
  set -e
  if [[ ! -s "$out" || "$rc" -gt 3 ]]; then
    echo "error: failed to render $json (exit $rc)" >&2
    [[ -n "$render_output" ]] && echo "$render_output" >&2
    exit 1
  fi
  printf '  %-30s -> %s\n' "$json" "$out"
  count=$((count + 1))
done

if [[ "$count" -eq 0 ]]; then
  echo "no fixtures found in $JSON_DIR/" >&2
  exit 1
fi
echo "rendered $count example(s)."
