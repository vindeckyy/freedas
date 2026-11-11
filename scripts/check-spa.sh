#!/usr/bin/env bash
# Parse the SPA's inline JavaScript. The web UI is one HTML file, so nothing
# else in the build touches that script: a syntax error would ship a blank
# UI with a green CI. Skipped when node is not installed.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
html="$root/crates/freedas-web/assets/index.html"
if ! command -v node >/dev/null 2>&1; then
  echo "node not found: skipping the SPA syntax check"
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
awk '/<script>/{f=1;next} /<\/script>/{f=0} f' "$html" > "$tmp/spa.js"
if [ ! -s "$tmp/spa.js" ]; then
  echo "no inline script found in $html" >&2
  exit 1
fi
node --check "$tmp/spa.js"
echo "SPA script parses ($(wc -l < "$tmp/spa.js" | tr -d ' ') lines)"
