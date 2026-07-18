#!/usr/bin/env bash
# Generate CycloneDX SBOMs (Software Bill of Materials) for every Rust workspace (R-501, NIST SSDF).
# One SBOM per package, collected into sbom/. Requires cargo-cyclonedx:
#   cargo install cargo-cyclonedx --locked
# The output (sbom/*.cdx.json) is a build artifact — gitignored; CI uploads it per build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
OUT="$ROOT/sbom"
mkdir -p "$OUT"

for ws in services core/mls-core core/mls-ffi; do
  echo "== SBOM: $ws =="
  ( cd "$ROOT/$ws" && cargo cyclonedx --format json )
done
# Collect the per-package files (written next to each Cargo.toml) into sbom/.
find "$ROOT/services" "$ROOT/core" -name '*.cdx.json' -not -path '*/target/*' -not -path "$OUT/*" \
  -exec sh -c 'cp "$1" "'"$OUT"'/$(basename "$1")"' _ {} \;
# Remove the in-tree copies so only sbom/ holds them.
find "$ROOT/services" "$ROOT/core" -name '*.cdx.json' -not -path '*/target/*' -not -path "$OUT/*" -delete
echo "== SBOMs written to $OUT: =="
ls -1 "$OUT"
