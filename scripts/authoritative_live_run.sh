#!/usr/bin/env bash
# Live end-to-end run for MLS-commit-authoritative membership (ADR-0010, R-506). Boots nedwons-api
# against PostgreSQL and drives it with AuthoritativeLiveRun, which runs the FULL shipping stack —
# the real ConversationCoordinator over the real NedwonsClient over real HTTP, with the real Rust
# MLS core underneath — so intents, signed manifests, the epoch CAS, and recipient verification
# against the live transparency log are all proven with real bytes crossing the real relay.
#
# Requires: cargo, swift, a running PostgreSQL. Uses DATABASE_URL (default nedwons_dev).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATABASE_URL="${DATABASE_URL:-postgres://localhost/nedwons_dev}"
PORT="${PORT:-8099}"
BIND="127.0.0.1:${PORT}"

echo "== building nedwons-api =="
( cd "$ROOT/services" && cargo build -q -p nedwons-api )

echo "== starting server on ${BIND} =="
DATABASE_URL="$DATABASE_URL" NEDWONS_BIND="$BIND" NEDWONS_RATE_PER_MIN=100000 \
  "$ROOT/services/target/debug/nedwons-api" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Wait for health.
for _ in $(seq 1 30); do
  if curl -fsS "http://${BIND}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://${BIND}/healthz" >/dev/null || { echo "server did not become healthy"; exit 1; }
echo "server healthy"

echo "== running Swift live client (NedwonsClient + real MlsClient) =="
OUT="$(NEDWONS_URL="http://${BIND}" swift run --package-path "$ROOT/apps/ios/NedwonsApp" AuthoritativeLiveRun 2>&1)"
echo "$OUT"
echo "$OUT" | grep -q "LIVE_OK"
echo "== authoritative_live_run: PASS =="
