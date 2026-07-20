#!/usr/bin/env bash
# Generate STABLE server signing keys (BN-3). In dev the server mints EPHEMERAL transparency-log and
# sender-certificate keys on each start — which invalidates anything a client pinned and breaks the
# key-transparency self-audit across restarts. Before device testing, generate stable keys once and
# hold them in your secrets store, then export them to the server:
#
#   NEDWONS_LOG_SIGNING_KEY  — the transparency log's ECDSA P-256 private scalar (32-byte hex).
#                               Its PUBLIC key is what clients pin (NedwonsTransparencyLogKey).
#   NEDWONS_SENDER_CERT_KEY  — the sealed-sender certificate signing key (ECDSA P-256, 32-byte hex).
#
# A random 32-byte value is a valid P-256 scalar with overwhelming probability; the server rejects
# the negligible invalid case at startup, so just re-run if that ever happens.
#
# Usage:
#   scripts/gen_server_keys.sh            # print the two keys
#   scripts/gen_server_keys.sh --env      # also print the client-pinned log PUBLIC key (needs the
#                                         # server built, to derive it) — see the note below
set -euo pipefail

log_key="$(openssl rand -hex 32)"
cert_key="$(openssl rand -hex 32)"

cat <<EOF
# --- Stable server signing keys (keep SECRET; store in your secrets manager) ---
NEDWONS_LOG_SIGNING_KEY=${log_key}
NEDWONS_SENDER_CERT_KEY=${cert_key}
EOF

cat <<'EOF'

# Next steps:
# 1. Export these into the server's environment (do NOT commit them).
# 2. The client must PIN the transparency log's PUBLIC key. Start the server once with the key
#    above set, then GET /v1/transparency/sth and copy the "log_public_key" (hex) into the app's
#    build config as `NedwonsTransparencyLogKey` (Info.plist). From then on the app trusts that
#    exact key instead of TOFU-accepting whatever the server advertises.
EOF
