#!/usr/bin/env bash
# The review team's terminal tool for the report queue (docs/MODERATION.md).
#
#   NEDWONS_SERVER_URL=https://api.example NEDWONS_MODERATION_TOKEN=... NEDWONS_REVIEWER=alice \
#     scripts/review_reports.sh list
#     scripts/review_reports.sh show 42          # full report; media saved to a temp file
#     scripts/review_reports.sh ban 42 "CSAM, verified"      # resolve + ban the reported account
#     scripts/review_reports.sh dismiss 42 "not actionable"  # resolve, no action
#     scripts/review_reports.sh bans
#     scripts/review_reports.sh unban <account-hex>
#
# Requires: curl, jq, xxd. The token is the deployment's NEDWONS_MODERATION_TOKEN; the reviewer
# handle is recorded in the audit trail on every action. Review standards are LEGALITY-scoped —
# read docs/MODERATION.md before actioning anything.
set -euo pipefail

BASE="${NEDWONS_SERVER_URL:?set NEDWONS_SERVER_URL}"
TOKEN="${NEDWONS_MODERATION_TOKEN:?set NEDWONS_MODERATION_TOKEN}"
REVIEWER="${NEDWONS_REVIEWER:-$(whoami)}"

api() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS -X "$method" "$BASE$path" \
      -H "x-moderation-token: $TOKEN" -H "Content-Type: application/json" -d "$body"
  else
    curl -fsS -X "$method" "$BASE$path" -H "x-moderation-token: $TOKEN"
  fi
}

case "${1:-help}" in
  list)
    api GET /v1/moderation/reports | jq -r '
      .reports[] |
      "#\(.id)  [\(.category)]  reported=\(.reported[0:8])…  media=\(if .has_media then "yes" else "no" end)\n    \(.reason)"'
    ;;
  show)
    id="${2:?usage: show <id>}"
    out="$(api GET "/v1/moderation/reports/$id")"
    echo "$out" | jq '{report, evidence_media_mime}'
    media="$(echo "$out" | jq -r '.evidence_media // empty')"
    if [ -n "$media" ]; then
      mime="$(echo "$out" | jq -r '.evidence_media_mime // "bin"')"
      ext="${mime##*/}"
      file="$(mktemp -t "nedwons-report-$id").${ext}"
      echo "$media" | xxd -r -p > "$file"
      echo "evidence media saved to: $file"
    fi
    ;;
  ban|dismiss)
    id="${2:?usage: $1 <id> [note]}"
    note="${3:-}"
    api POST "/v1/moderation/reports/$id/resolve" \
      "$(jq -n --arg a "$1" --arg r "$REVIEWER" --arg n "$note" '{action:$a, reviewer:$r, note:$n}')"
    echo "report #$id: $1 (by $REVIEWER)"
    ;;
  bans)
    api GET /v1/moderation/bans | jq -r '
      .bans[] | "\(.account_id)  by \(.banned_by)  report=\(.report_id // "-")\n    \(.reason)"'
    ;;
  unban)
    acct="${2:?usage: unban <account-hex>}"
    api POST /v1/moderation/unban "$(jq -n --arg a "$acct" '{account_id:$a}')"
    echo "unbanned $acct"
    ;;
  *)
    grep '^#   ' "$0" | sed 's/^#   //'
    ;;
esac
