#!/usr/bin/env bash
# Live integration proof: boot the real sentinel-api server against PostgreSQL, then run the
# Swift SentinelSmoke client against it over real HTTP (register -> whoami -> login -> whoami,
# plus the INV-2 negative check that a different device cannot log in). Verifies the iOS
# client interoperates with the Rust backend end to end.
#
# Requires: cargo, swift, a running PostgreSQL. Uses DATABASE_URL (default sentinel_dev).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATABASE_URL="${DATABASE_URL:-postgres://localhost/sentinel_dev}"
PORT="${PORT:-8097}"
BIND="127.0.0.1:${PORT}"

echo "== building sentinel-api =="
( cd "$ROOT/services" && cargo build -q -p sentinel-api )

echo "== starting server on ${BIND} =="
DATABASE_URL="$DATABASE_URL" SENTINEL_BIND="$BIND" SENTINEL_RATE_PER_MIN=100000 \
  "$ROOT/services/target/debug/sentinel-api" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Wait for health.
for _ in $(seq 1 30); do
  if curl -fsS "http://${BIND}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://${BIND}/healthz" >/dev/null || { echo "server did not become healthy"; exit 1; }
echo "server healthy"

echo "== running Swift smoke client =="
OUT="$(SENTINEL_URL="http://${BIND}" swift run --package-path "$ROOT/apps/ios/SentinelKit" SentinelSmoke 2>&1)"
echo "$OUT"
echo "$OUT" | grep -q "SMOKE_OK"
echo "== swift_backend_smoke: PASS =="
