#!/usr/bin/env bash
# Run a Swift command and, when it fails under GitHub Actions, republish its first compile errors
# as workflow annotations.
#
# WHY THIS EXISTS
# Reading a failed job's raw log requires repo-ADMIN rights. Without it, a failing `swift build`
# surfaces to everyone else as exactly one line — "Process completed with exit code 1" — which says
# nothing about which file, which line, or which diagnostic. The XCUITest job had the same blindness
# and cost a day of guessing before `scripts/test_ui_sim.sh` started annotating; this is the same
# medicine for the two SwiftPM jobs.
#
# Errors are taken from the TOP, in the compiler's own order and deduplicated, because a compiler
# reports the root cause first and the tail is usually consequences of it.
#
# Usage: scripts/annotate_swift.sh swift build
#        scripts/annotate_swift.sh swift test
set -uo pipefail

LOG="$(mktemp)"
"$@" >"$LOG" 2>&1
STATUS=$?

# Always show a bounded tail so the console still reads normally for anyone who CAN see the log.
tail -80 "$LOG"

if [ "$STATUS" -ne 0 ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
  # `file.swift:line:col: error: …` — a real compile diagnostic. Deduplicated with awk rather than
  # `sort -u`, which is lexical and would rank ":103:" above ":39:", burying the first error.
  ERRORS="$(grep -hoE "[^ ]+\.swift:[0-9]+:[0-9]+: error: .*" "$LOG" | awk '!seen[$0]++' || true)"
  LABEL="Swift build error"
  if [ -z "$ERRORS" ]; then
    # No compile diagnostic: a failing test, a linker error, or a toolchain problem. Fall back to
    # whatever mentions failure, from the END, where a test summary lives.
    ERRORS="$(grep -E "error:|error;|XCTAssert|failed|Fatal error" "$LOG" | tail -10 || true)"
    LABEL="Swift failure"
  fi

  TOTAL="$(printf '%s' "$ERRORS" | grep -c . || true)"
  printf '%s\n' "$ERRORS" | head -10 | while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '::error title=%s::%s\n' "$LABEL" "$(printf '%s' "$line" | tr -d '\r' | cut -c1-400)"
  done
  if [ "${TOTAL:-0}" -gt 10 ]; then
    printf '::error title=%s::… and %s more\n' "$LABEL" "$((TOTAL - 10))"
  fi
fi

rm -f "$LOG"
exit $STATUS
